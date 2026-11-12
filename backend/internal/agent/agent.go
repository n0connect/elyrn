package agent

import (
	"context"
	"net/http"

	"elyrn/internal/e2e"
	"elyrn/internal/identity"
	"elyrn/internal/models"
	"elyrn/internal/utils"

	"github.com/google/uuid"
)

// Config names the server (optional once the identity file holds one) and the identity file.
type Config struct {
	Server       string
	IdentityPath string
}

// Agent is one account on one server. Its public methods are serialized: one call at a time.
type Agent struct {
	origin string
	idPath string
	client *http.Client
	lock   *utils.SafeMutex

	// Derived from the AccountNumber when the identity is loaded; the number itself is not kept.
	authKey   string
	publicKey string
	root      []byte

	session *http.Cookie
	limits  *models.MeResponse
	rooms   map[uuid.UUID]*roomState
}

// New validates the server address, loads the identity file if there is one, and checks that
// both agree. It touches no network.
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
	stored, err := loadIdentity(cfg.IdentityPath)
	if err != nil {
		return nil, err
	}
	proxy, err := proxyFunc()
	if err != nil {
		return nil, err
	}
	a := &Agent{
		idPath: cfg.IdentityPath,
		client: newHTTPClient(proxy),
		lock:   utils.NewSafeMutexWithTimeout(callLockTimeout),
		rooms:  make(map[uuid.UUID]*roomState),
	}
	if stored != nil {
		if origin != "" && origin != stored.Server {
			return nil, fail(CodeServerMismatch, nil)
		}
		origin = stored.Server
		if err := a.adoptIdentity(stored.AccountNumber); err != nil {
			return nil, err
		}
	}
	a.origin = origin
	if origin != "" {
		if err := requireProxyForOnion(origin, proxy); err != nil {
			return nil, err
		}
	}
	return a, nil
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

// Close wipes the rooms root; the agent is unusable afterwards.
func (a *Agent) Close() {
	zeroBytes(a.root)
	a.root = nil
	a.rooms = nil
	a.session = nil
}

// serialized runs one public call under the agent's lock.
func (a *Agent) serialized(call func() error) error {
	if err := a.lock.Lock(); err != nil {
		return fail(CodeBusy, err)
	}
	defer a.lock.Unlock()
	return call()
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
