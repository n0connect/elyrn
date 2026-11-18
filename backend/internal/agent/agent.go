package agent

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"elyrn/internal/e2e"
	"elyrn/internal/identity"
	"elyrn/internal/models"
	"elyrn/internal/utils"

	"github.com/google/uuid"
)

// Config names the server (optional once the identity file holds one) and the identity file.
// ReadOnly loads the identity without taking its lock or its counter file: such an agent
// answers Whoami only, and may run beside the agent that holds the identity.
type Config struct {
	Server       string
	IdentityPath string
	ReadOnly     bool
}

// Agent is one account on one server. Its public methods are serialized: one call at a time.
type Agent struct {
	origin   string
	idPath   string
	readOnly bool
	client   *http.Client
	lock     *utils.SafeMutex
	closed   bool     // guarded by lock
	held     *os.File // the identity lock, held for the agent's life (nil when read-only)

	// Derived from the AccountNumber when the identity is loaded; the number itself is not kept.
	authKey   string
	publicKey string
	root      []byte
	// pendingToken is set while the account is not confirmed yet (registration phase 2 to redo).
	pendingToken string

	session  *http.Cookie
	limits   *models.MeResponse
	rooms    map[uuid.UUID]*roomState
	counters *counterState
}

// New validates the server address, takes the identity's lock (unless read-only), loads the
// identity file if there is one and the counter file beside it, and checks that the address
// and the identity agree. It touches no network.
func New(cfg Config) (*Agent, error) {
	origin := ""
	if cfg.Server != "" {
		var kind URLKind
		if origin, kind = ClassifyServerURL(cfg.Server); kind == URLRefused {
			return nil, fail(CodeServerURL, nil)
		}
	}
	if cfg.IdentityPath == "" {
		return nil, fail(CodeIdentityFile, nil)
	}
	a := &Agent{
		idPath:   cfg.IdentityPath,
		readOnly: cfg.ReadOnly,
		lock:     utils.NewSafeMutexWithTimeout(callLockTimeout),
		rooms:    make(map[uuid.UUID]*roomState),
	}
	if !cfg.ReadOnly {
		if err := a.takeIdentityLock(); err != nil {
			return nil, err
		}
	}
	if err := a.load(origin); err != nil {
		a.releaseIdentityLock()
		return nil, err
	}
	return a, nil
}

// takeIdentityLock holds agent.json.lock for the agent's life (second process: fails fast with
// E_AGENT_IDENTITY_IN_USE), then sweeps temporary files an interrupted write left behind.
func (a *Agent) takeIdentityLock() error {
	dir := filepath.Dir(a.idPath)
	if err := ensurePrivateDir(dir, CodeIdentityFile); err != nil {
		return err
	}
	held, err := lockFile(lockPath(a.idPath))
	if err != nil {
		return err
	}
	a.held = held
	sweepTemps(dir)
	return nil
}

func (a *Agent) releaseIdentityLock() {
	if a.held != nil {
		// Closing the descriptor drops the flock whatever Close reports, and the agent is done
		// with the file: there is nothing to retry and nothing to tell the caller
		_ = a.held.Close()
		a.held = nil
	}
}

// load reads the identity and, for a writable agent, the counter file.
func (a *Agent) load(origin string) error {
	stored, err := loadIdentity(a.idPath)
	if err != nil {
		return err
	}
	if stored != nil {
		if origin != "" && origin != stored.Server {
			return fail(CodeServerMismatch, nil)
		}
		origin = stored.Server
		if err := a.adoptIdentity(stored.AccountNumber); err != nil {
			return err
		}
		a.pendingToken = stored.PendingToken
	}
	a.origin = origin
	// Chosen once the origin is known: an onion origin has a route of its own (proxyFor)
	proxy, err := proxyFor(origin)
	if err != nil {
		return err
	}
	a.client = newHTTPClient(proxy)
	if !a.readOnly {
		if a.counters, err = loadCounterState(statePath(a.idPath), stored != nil); err != nil {
			return err
		}
	}
	return nil
}

// RequireServer fails unless a server is known (from --server or the identity file).
func (a *Agent) RequireServer() error {
	if a.origin == "" {
		return fail(CodeServerMissing, nil)
	}
	return nil
}

// adoptIdentity derives what the agent needs from the AccountNumber and keeps nothing else.
func (a *Agent) adoptIdentity(accountNumber string) error {
	authKey, err := identity.DeriveAuthKey(accountNumber)
	if err != nil {
		return fail(CodeIdentityFile, err)
	}
	publicKey, err := identity.DerivePublicKey(accountNumber)
	if err != nil {
		return fail(CodeIdentityFile, err)
	}
	root, err := e2e.RoomsRoot(accountNumber)
	if err != nil {
		return fail(CodeIdentityFile, err)
	}
	a.authKey, a.publicKey, a.root = authKey, publicKey, root
	return nil
}

// Close waits (at most shutdownWait) for the call in flight to return, which a cancelled
// context makes prompt, then wipes the rooms root and releases the identity lock; the agent
// refuses every call afterwards. If the call does not return in time, nothing is touched under
// it: the process is ending anyway, and the operating system releases the lock. Close may be
// called more than once.
func (a *Agent) Close() {
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		a.closeAfterCall()
	}()
	timer := time.NewTimer(shutdownWait)
	defer timer.Stop()
	select {
	case <-closed:
	case <-timer.C:
		logger.Warn("the call in flight did not end within the shutdown bound")
	}
}

// closeAfterCall takes the call lock, so it runs once the call in flight has returned.
func (a *Agent) closeAfterCall() {
	if err := a.lock.Lock(); err != nil {
		return
	}
	defer a.lock.Unlock()
	a.closed = true
	zeroBytes(a.root)
	a.root = nil
	a.rooms = nil
	a.session = nil
	a.limits = nil
	a.pendingToken = ""
	a.releaseIdentityLock()
}

// serialized runs one public call under the agent's lock.
func (a *Agent) serialized(call func() error) error {
	if err := a.lock.Lock(); err != nil {
		return fail(CodeBusy, err)
	}
	defer a.lock.Unlock()
	if a.closed {
		return fail(CodeStopped, nil)
	}
	return call()
}

// requireWritable refuses network calls on a read-only agent (Whoami is all it answers).
func (a *Agent) requireWritable() error {
	if a.readOnly {
		return fail(CodeInternal, nil)
	}
	return nil
}

// Identity creates the account on first use (two proofs of work), logs in, and reports the
// public identity. The AccountNumber is never part of any result.
func (a *Agent) Identity(ctx context.Context) (*IdentityResult, error) {
	var result *IdentityResult
	err := a.serialized(func() error {
		created, err := a.ensureAccount(ctx)
		if err != nil {
			return err
		}
		if err := a.ensureSession(ctx); err != nil {
			return err
		}
		result, err = a.identityResult(created)
		return err
	})
	return result, err
}

// Whoami reports the stored identity without contacting the server.
func (a *Agent) Whoami() (*IdentityResult, error) {
	var result *IdentityResult
	err := a.serialized(func() error {
		if a.authKey == "" {
			return fail(CodeIdentityMissing, nil)
		}
		var err error
		result, err = a.identityResult(false)
		return err
	})
	return result, err
}

func (a *Agent) identityResult(created bool) (*IdentityResult, error) {
	raw, ok := utils.DecodeExact(a.publicKey, identity.KeySize)
	if !ok {
		return nil, fail(CodeInternal, nil)
	}
	aura, err := e2e.AuraOf(raw)
	if err != nil {
		return nil, fail(CodeInternal, err)
	}
	return &IdentityResult{Name: aura.Name, Code: aura.Code, PublicKey: a.publicKey, Server: a.origin, Created: created}, nil
}
