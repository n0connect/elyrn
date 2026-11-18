package agent

import (
	"context"
	"net/http"

	"elyrn/internal/e2e"
	"elyrn/internal/models"

	"github.com/google/uuid"
)

// ValidateRoleText is e2e.ValidateRoleText (the one home of the role rule) under the agent's
// code: it returns the role as it will be sealed, in NFC.
func ValidateRoleText(role string) (string, error) {
	normalized, err := e2e.ValidateRoleText(role)
	if err != nil {
		return "", fail(CodeRoleText, err)
	}
	return normalized, nil
}

// SetRole seals role ("" clears) for one member of a room and stores it on the server, which lets
// the owner set anyone's role and any other member only its own (403 otherwise). member is a
// member's code as Members lists it, "" for this agent. The role is sealed for the target's card
// as just served, so the server can neither read it nor move it to another member.
func (a *Agent) SetRole(ctx context.Context, id uuid.UUID, member, role string) (*RoleSet, error) {
	var result *RoleSet
	err := a.serialized(func() error {
		normalized, err := ValidateRoleText(role)
		if err != nil {
			return err
		}
		if member != "" && !e2e.IsAuraCode(member) {
			return fail(CodeArgument, nil)
		}
		st, err := a.room(ctx, id)
		if err != nil {
			return err
		}
		if st.expired() {
			return fail(CodeRoomExpired, nil)
		}
		if err := a.loadRoster(ctx, st); err != nil {
			return err
		}
		target, err := st.roleTarget(member)
		if err != nil {
			return err
		}
		blob, err := st.keys.SealRole(target.card, normalized)
		if err != nil {
			return fail(CodeInternal, err)
		}
		status, err := a.api(ctx, http.MethodPost, conversationPath(st.id)+pathMembers, models.SetRoleRequest{Card: target.card, Role: blob}, nil)
		switch {
		case err != nil:
			return err
		case status == http.StatusNoContent:
			target.role = normalized
			result = &RoleSet{Room: st.id.String(), Name: target.aura.Name, Code: target.aura.Code, Role: normalized}
			return nil
		case status == http.StatusForbidden:
			return fail(CodeRoleNotAllowed, nil)
		case status == http.StatusNotFound:
			// The room is gone or the member left since the roster was read: one answer for both
			return fail(CodeRoleMemberGone, nil)
		default:
			return statusError(status)
		}
	})
	return result, err
}

// roleTarget is the verified member a role is for: this agent when member is "", else the one
// member whose aura code is member. Two members may share a code (it is two bytes of a digest):
// then nothing is set rather than the wrong member's role.
func (st *roomState) roleTarget(member string) (*rosterEntry, error) {
	var found *rosterEntry
	for i := range st.roster {
		entry := &st.roster[i]
		if (member == "" && !entry.mine) || (member != "" && entry.aura.Code != member) {
			continue
		}
		if found != nil {
			return nil, fail(CodeRoleMemberAmbiguous, nil)
		}
		found = entry
	}
	if found == nil {
		return nil, fail(CodeRoleMemberUnknown, nil)
	}
	if found.disputed() {
		// Which of its cards is the member's cannot be told: a role sealed for one may land on
		// the seat of whoever copied the key (rooms.js mayRole)
		return nil, fail(CodeRoleMemberDisputed, nil)
	}
	return found, nil
}
