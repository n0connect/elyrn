package agent

import (
	"context"
	"errors"
	"net/http"
	"time"

	"elyrn/internal/e2e"
	"elyrn/internal/models"

	"github.com/google/uuid"
)

// Send encrypts text for the room's verified roster and stores it, as chat.js send does:
// a 412 (someone joined or left) fetches the roster again and re-encrypts under the same
// message id, twice at most; a lost answer resends the same id and ciphertext, and a 409 then
// means the first attempt was stored.
func (a *Agent) Send(ctx context.Context, id uuid.UUID, text string) (*Sent, error) {
	var result *Sent
	err := a.serialized(func() error {
		normalized, err := ValidateMessageText(text)
		if err != nil {
			return err
		}
		st, err := a.room(ctx, id)
		if err != nil {
			return err
		}
		if !time.Now().Before(st.expiresAt) {
			return fail(CodeRoomExpired, nil)
		}
		if err := a.prepareSend(ctx, st); err != nil {
			return err
		}
		result, err = a.deliver(ctx, st, normalized)
		return err
	})
	return result, err
}

// prepareSend makes the counter final and the roster known.
func (a *Agent) prepareSend(ctx context.Context, st *roomState) error {
	if err := a.syncCounters(ctx, st); err != nil {
		return err
	}
	if st.rosterCards == nil {
		return a.loadRoster(ctx, st)
	}
	return nil
}

// spendCounter takes this account's next counter in the room and persists it before anything
// is sent (write-ahead): max(remembered, rebuilt from the visible messages) + 1, so neither a
// restart nor a lost answer ever reuses one. Without a durable record nothing is sent.
func (a *Agent) spendCounter(st *roomState) (int64, error) {
	if st.counters.Mine >= maxSafeSeq {
		return 0, fail(CodeStateFile, nil)
	}
	counter := st.counters.Mine + 1
	st.counters.raiseMine(counter)
	if err := a.persistCounters(); err != nil {
		return 0, err
	}
	return counter, nil
}

// deliver runs the bounded exchange loop of one message.
func (a *Agent) deliver(ctx context.Context, st *roomState, text string) (*Sent, error) {
	messageID := uuid.New()
	counter, err := a.spendCounter(st)
	if err != nil {
		return nil, err
	}
	blob, err := a.seal(st, messageID, text, counter)
	if err != nil {
		return nil, err
	}
	rosterRetries, lostRetries := 0, 0
	for exchange := 0; exchange <= maxRosterRetries+maxLostAnswerRetries; exchange++ {
		var resp models.SendMessageResponse
		status, err := a.api(ctx, http.MethodPost, conversationPath(st.id)+pathMessages,
			models.SendMessageRequest{ID: messageID.String(), Ciphertext: blob}, &resp)
		lost := (err != nil && CodeOf(err) == CodeNetwork) || (err == nil && status >= http.StatusInternalServerError)
		switch {
		case lost:
			// The outcome is open: the counter was spent before the first attempt
			if lostRetries == maxLostAnswerRetries {
				return nil, fail(CodeSendUncertain, err)
			}
			lostRetries++
			if err := backoff(ctx, lostRetries); err != nil {
				return nil, err
			}
		case err != nil:
			return nil, err
		case status == http.StatusCreated:
			if resp.Seq < 1 || resp.Seq > maxSafeSeq {
				return nil, fail(CodeServerAnswer, nil)
			}
			return &Sent{Room: st.id.String(), Seq: &resp.Seq, Stored: true}, nil
		case status == http.StatusConflict && lostRetries > 0:
			return &Sent{Room: st.id.String(), Stored: true}, nil
		case status == http.StatusPreconditionFailed:
			if rosterRetries == maxRosterRetries {
				return nil, fail(CodeRosterChanged, nil)
			}
			rosterRetries++
			if blob, err = a.reseal(ctx, st, messageID, text, counter); err != nil {
				return nil, err
			}
		case status == http.StatusNotFound:
			return nil, a.forget(st.id)
		default:
			return nil, statusError(status)
		}
	}
	return nil, fail(CodeSendUncertain, nil)
}

// reseal fetches the roster again and encrypts the same message for it.
func (a *Agent) reseal(ctx context.Context, st *roomState, messageID uuid.UUID, text string, counter int64) (string, error) {
	if err := a.loadRoster(ctx, st); err != nil {
		return "", err
	}
	return a.seal(st, messageID, text, counter)
}

// seal encrypts for every verified member of the roster as served (rooms.js seal).
func (a *Agent) seal(st *roomState, messageID uuid.UUID, text string, counter int64) (string, error) {
	recipients, digest, err := st.keys.Recipients(st.member, st.rosterCards)
	if err != nil {
		return "", fail(CodeRoster, err)
	}
	if len(recipients) > st.maxMembers {
		return "", fail(CodeRoster, nil)
	}
	blob, err := st.keys.SealMessage(st.member, messageID, recipients, digest, text, time.Now().UnixMilli(), counter)
	if errors.Is(err, e2e.ErrInvalidInput) {
		return "", fail(CodeMessageText, err) // the text does not fit one frame
	}
	if err != nil {
		return "", fail(CodeInternal, err)
	}
	return blob, nil
}
