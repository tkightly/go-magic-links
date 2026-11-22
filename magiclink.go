// Package magiclink signs people in with emailed, single-use links and keeps
// them signed in with opaque session tokens.
//
// It owns everything about the mechanism: random tokens (only their SHA-256
// is stored), link expiry and single use, sessions, rate limits on link
// requests and verifications, and pruning of expired rows. The app supplies
// policy through three hooks, each run inside the module's transaction:
//
//   - Allow decides who may be sent a link.
//   - Send queues the email (in the app's outbox, through the same tx).
//   - SignIn turns a verified email into the app's user ID, creating the
//     user or doing anything else that must happen atomically with sign-in.
//
// The module uses SQLite through database/sql and creates its own tables
// (prefixed magiclink_) in New.
package magiclink

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/tkightly/go-magic-links/internal/ratelimit"
)

var (
	// ErrInvalidLink means the link is unknown, expired or already used.
	ErrInvalidLink = errors.New("magiclink: link is invalid, expired or already used")
	// ErrUnauthorized means the session token is missing, unknown or expired.
	ErrUnauthorized = errors.New("magiclink: not signed in")
	// ErrRateLimited means the caller should wait before trying again. It is
	// returned whether or not the address may sign in, so it reveals nothing.
	ErrRateLimited = errors.New("magiclink: too many requests")
)

// Link is a sign-in link as the hooks see it.
type Link struct {
	// Email is trimmed and lower-cased.
	Email string
	// URL is the address to put in the email. Only set for Send.
	URL       string
	ExpiresAt time.Time
	// State is whatever was passed to SendLink, JSON-encoded; nil if none.
	// Use it to carry what should happen on sign-in (e.g. "join group 7").
	State json.RawMessage
}

// Session is a signed-in user.
type Session struct {
	// Token is the session token to hand to the browser. Only set by Verify.
	Token string
	// UserID is whatever SignIn returned for this user.
	UserID    string
	Email     string
	ExpiresAt time.Time
}

// Config configures an Auth. DB, LinkURL, Send and SignIn are required.
type Config struct {
	// DB must be SQLite. Code inside the hooks must use only the tx it is
	// given: with a one-connection pool, touching DB there deadlocks.
	DB *sql.DB

	// LinkURL is the page that verifies links, e.g.
	// "https://app.example.com/auth/verify". The token is added as the
	// "token" query parameter.
	LinkURL string

	// Allow reports whether a link may be sent. When it says no, the module
	// does the same work and rolls it back, so neither the response nor its
	// timing reveals who may sign in. An error is returned to the caller
	// unchanged. Nil allows everyone.
	Allow func(ctx context.Context, tx *sql.Tx, l Link) (bool, error)

	// Send queues the sign-in email. It must only write through tx (e.g. to
	// an outbox table), never deliver directly: the tx is rolled back when
	// Allow said no, or if anything later fails. Errors are returned to the
	// caller unchanged, whether or not the address was allowed.
	Send func(ctx context.Context, tx *sql.Tx, l Link) error

	// AfterSend, if set, runs once a queued email has been committed (never
	// for disallowed addresses), e.g. to wake the app's outbox worker.
	AfterSend func()

	// SignIn runs when a link is verified, and returns the ID of the user
	// the session belongs to, as an opaque string (an integer ID formatted
	// with strconv, a UUID, ...). It typically creates the user on first
	// sign-in.
	// Returning an error aborts sign-in and leaves the link unused; the
	// error is returned from Verify unchanged.
	SignIn func(ctx context.Context, tx *sql.Tx, l Link) (userID string, err error)

	// LinkTTL defaults to 15 minutes, SessionTTL to 30 days.
	LinkTTL    time.Duration
	SessionTTL time.Duration

	Limits Limits

	// Now is the clock, for tests. Defaults to time.Now.
	Now func() time.Time
}

// Limits are in-memory sliding windows; they reset when the process
// restarts. Zero values take the defaults.
type Limits struct {
	LinksPerIPPerHour     int // default 10
	LinksPerEmailPer15Min int // default 3
	LinksPerEmailPerDay   int // default 10
	VerifiesPerIPPerHour  int // default max(30, 3 × LinksPerIPPerHour)
}

// Auth signs people in. It is safe for concurrent use.
type Auth struct {
	cfg Config

	linksPerIP       *ratelimit.Limiter
	linksPerEmail    *ratelimit.Limiter
	linksPerEmailDay *ratelimit.Limiter
	verifiesPerIP    *ratelimit.Limiter
}

// New checks cfg and creates or upgrades the module's tables.
func New(ctx context.Context, cfg Config) (*Auth, error) {
	if cfg.DB == nil || cfg.Send == nil || cfg.SignIn == nil {
		return nil, errors.New("magiclink: DB, Send and SignIn are required")
	}
	if u, err := url.Parse(cfg.LinkURL); err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("magiclink: LinkURL must be an absolute URL, got %q", cfg.LinkURL)
	}
	if cfg.LinkTTL <= 0 {
		cfg.LinkTTL = 15 * time.Minute
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 30 * 24 * time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	l := &cfg.Limits
	l.LinksPerIPPerHour = orDefault(l.LinksPerIPPerHour, 10)
	l.LinksPerEmailPer15Min = orDefault(l.LinksPerEmailPer15Min, 3)
	l.LinksPerEmailPerDay = orDefault(l.LinksPerEmailPerDay, 10)
	l.VerifiesPerIPPerHour = orDefault(l.VerifiesPerIPPerHour, max(30, 3*l.LinksPerIPPerHour))

	if err := migrate(ctx, cfg.DB); err != nil {
		return nil, fmt.Errorf("magiclink: migrate tables: %w", err)
	}
	return &Auth{
		cfg:              cfg,
		linksPerIP:       ratelimit.New(l.LinksPerIPPerHour, time.Hour).WithClock(cfg.Now),
		linksPerEmail:    ratelimit.New(l.LinksPerEmailPer15Min, 15*time.Minute).WithClock(cfg.Now),
		linksPerEmailDay: ratelimit.New(l.LinksPerEmailPerDay, 24*time.Hour).WithClock(cfg.Now),
		verifiesPerIP:    ratelimit.New(l.VerifiesPerIPPerHour, time.Hour).WithClock(cfg.Now),
	}, nil
}

// SendLink emails a sign-in link to email, if Allow permits. It returns nil
// when Allow says no, so callers can always answer "if that address can sign
// in, we've sent a link". state, if not nil, is JSON-encoded and handed back
// to the hooks as Link.State. clientIP is used only for rate limiting.
func (a *Auth) SendLink(ctx context.Context, email, clientIP string, state any) error {
	email = normalizeEmail(email)
	if email == "" {
		return errors.New("magiclink: email is empty")
	}
	var stateJSON json.RawMessage
	if state != nil {
		b, err := json.Marshal(state)
		if err != nil {
			return fmt.Errorf("magiclink: encode state: %w", err)
		}
		stateJSON = b
	}
	// Check every limit before recording any, so a refused request doesn't
	// use up the others. Limits apply whether or not the address is allowed.
	if a.linksPerIP.Exceeded(clientIP) || a.linksPerEmail.Exceeded(email) || a.linksPerEmailDay.Exceeded(email) {
		return ErrRateLimited
	}
	a.linksPerIP.Record(clientIP)
	a.linksPerEmail.Record(email)
	a.linksPerEmailDay.Record(email)

	token := newToken()
	now := a.cfg.Now()
	link := Link{
		Email:     email,
		URL:       a.linkURL(token),
		ExpiresAt: now.Add(a.cfg.LinkTTL),
		State:     stateJSON,
	}
	err := a.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM magiclink_links WHERE expires_at <= ?`, now.Unix()); err != nil {
			return err
		}
		allowed := true
		if a.cfg.Allow != nil {
			hookLink := link
			hookLink.URL = ""
			var err error
			if allowed, err = a.cfg.Allow(ctx, tx, hookLink); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO magiclink_links (token_hash, email, state, expires_at) VALUES (?, ?, ?, ?)`,
			hashToken(token), email, nullable(stateJSON), link.ExpiresAt.Unix()); err != nil {
			return err
		}
		if err := a.cfg.Send(ctx, tx, link); err != nil {
			return err
		}
		if !allowed {
			return errDiscard
		}
		return nil
	})
	if errors.Is(err, errDiscard) {
		return nil
	}
	if err == nil && a.cfg.AfterSend != nil {
		a.cfg.AfterSend()
	}
	return err
}

// Verify consumes a link's token and starts a session. The Link is returned
// too, so the caller can act on its State (e.g. choose where to redirect).
// clientIP is used only for rate limiting.
func (a *Auth) Verify(ctx context.Context, token, clientIP string) (Session, Link, error) {
	if !plausibleToken(token) {
		return Session{}, Link{}, ErrInvalidLink
	}
	if !a.verifiesPerIP.Allow(clientIP) {
		return Session{}, Link{}, ErrRateLimited
	}
	var (
		sess Session
		link Link
	)
	err := a.inTx(ctx, func(tx *sql.Tx) error {
		now := a.cfg.Now()
		var (
			state   sql.NullString
			expires int64
		)
		// Single use: deleting is the claim. If anything below fails, the
		// rollback restores the link.
		err := tx.QueryRowContext(ctx, `
			DELETE FROM magiclink_links WHERE token_hash = ? AND expires_at > ?
			RETURNING email, state, expires_at`,
			hashToken(token), now.Unix()).Scan(&link.Email, &state, &expires)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInvalidLink
		}
		if err != nil {
			return err
		}
		link.ExpiresAt = time.Unix(expires, 0)
		if state.Valid {
			link.State = json.RawMessage(state.String)
		}

		userID, err := a.cfg.SignIn(ctx, tx, link)
		if err != nil {
			return err
		}
		if userID == "" {
			return errors.New("magiclink: SignIn returned an empty user ID")
		}

		if _, err := tx.ExecContext(ctx, `DELETE FROM magiclink_sessions WHERE expires_at <= ?`, now.Unix()); err != nil {
			return err
		}
		sess = Session{
			Token:     newToken(),
			UserID:    userID,
			Email:     link.Email,
			ExpiresAt: now.Add(a.cfg.SessionTTL),
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO magiclink_sessions (token_hash, user_id, email, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?)`,
			hashToken(sess.Token), userID, link.Email, now.Unix(), sess.ExpiresAt.Unix())
		return err
	})
	if err != nil {
		return Session{}, Link{}, err
	}
	return sess, link, nil
}

// Authenticate returns the session a token belongs to, or ErrUnauthorized.
// The returned Session's Token is the one passed in.
func (a *Auth) Authenticate(ctx context.Context, token string) (Session, error) {
	if !plausibleToken(token) {
		return Session{}, ErrUnauthorized
	}
	s := Session{Token: token}
	var expires int64
	err := a.cfg.DB.QueryRowContext(ctx, `
		SELECT user_id, email, expires_at FROM magiclink_sessions
		WHERE token_hash = ? AND expires_at > ?`,
		hashToken(token), a.cfg.Now().Unix()).Scan(&s.UserID, &s.Email, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrUnauthorized
	}
	if err != nil {
		return Session{}, err
	}
	s.ExpiresAt = time.Unix(expires, 0)
	return s, nil
}

// SignOut ends one session. Unknown tokens are ignored.
func (a *Auth) SignOut(ctx context.Context, token string) error {
	if !plausibleToken(token) {
		return nil
	}
	_, err := a.cfg.DB.ExecContext(ctx, `DELETE FROM magiclink_sessions WHERE token_hash = ?`, hashToken(token))
	return err
}

// SignOutUser ends every session of a user, e.g. when their access is
// revoked.
func (a *Auth) SignOutUser(ctx context.Context, userID string) error {
	_, err := a.cfg.DB.ExecContext(ctx, `DELETE FROM magiclink_sessions WHERE user_id = ?`, userID)
	return err
}

// --- internals -----------------------------------------------------------

// errDiscard rolls a transaction back without reporting a failure.
var errDiscard = errors.New("discard")

func (a *Auth) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := a.cfg.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (a *Auth) linkURL(token string) string {
	u, _ := url.Parse(a.cfg.LinkURL) // checked in New
	q := u.Query()
	q.Set("token", token)
	u.RawQuery = q.Encode()
	return u.String()
}

// tokenLen is the length of a base64url-encoded 32-byte token.
const tokenLen = 43

// newToken returns a 256-bit random token, base64url-encoded.
func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // never fails; panics internally if the OS can't supply randomness
	return base64.RawURLEncoding.EncodeToString(b)
}

// hashToken is stored in place of a token, so a leaked database can't be
// used to sign in.
func hashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// plausibleToken rejects input that can't be a token without touching the
// database.
func plausibleToken(t string) bool { return len(t) == tokenLen }

func normalizeEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

func nullable(b []byte) any {
	if b == nil {
		return nil
	}
	return string(b)
}

func orDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}
