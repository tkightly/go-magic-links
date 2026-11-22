package magiclink_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	magiclink "github.com/tkightly/go-magic-links"
	_ "modernc.org/sqlite"
)

// app is a minimal host app: a users table, an outbox, and an allowlist.
type app struct {
	db      *sql.DB
	auth    *magiclink.Auth
	now     time.Time
	allowed map[string]bool
	// sendErr, if set, is returned by the Send hook.
	sendErr error
	// signInErr, if set, is returned by the SignIn hook.
	signInErr error
	// woken counts AfterSend calls.
	woken int
}

func newApp(t *testing.T, mutate ...func(*magiclink.Config)) *app {
	t.Helper()
	db, err := sql.Open("sqlite", "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1) // as the apps do: a deadlock here means a hook used db, not tx
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`
		CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE);
		CREATE TABLE outbox (id INTEGER PRIMARY KEY, to_email TEXT NOT NULL, url TEXT NOT NULL, state TEXT);
	`); err != nil {
		t.Fatal(err)
	}
	a := &app{db: db, now: time.Unix(1_800_000_000, 0), allowed: map[string]bool{"amy@example.com": true}}
	cfg := magiclink.Config{
		DB:      db,
		LinkURL: "https://app.example.com/auth/verify?from=email",
		Now:     func() time.Time { return a.now },
		Allow: func(_ context.Context, _ *sql.Tx, l magiclink.Link) (bool, error) {
			return a.allowed[l.Email], nil
		},
		Send: func(ctx context.Context, tx *sql.Tx, l magiclink.Link) error {
			if a.sendErr != nil {
				return a.sendErr
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO outbox (to_email, url, state) VALUES (?, ?, ?)`, l.Email, l.URL, string(l.State))
			return err
		},
		AfterSend: func() { a.woken++ },
		SignIn: func(ctx context.Context, tx *sql.Tx, l magiclink.Link) (string, error) {
			if a.signInErr != nil {
				return "", a.signInErr
			}
			var id int64
			err := tx.QueryRowContext(ctx, `
				INSERT INTO users (email) VALUES (?) ON CONFLICT (email) DO UPDATE SET email = excluded.email
				RETURNING id`, l.Email).Scan(&id)
			return strconv.FormatInt(id, 10), err
		},
	}
	for _, m := range mutate {
		m(&cfg)
	}
	a.auth, err = magiclink.New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// outbox returns the queued emails' recipients and tokens.
func (a *app) outbox(t *testing.T) (to, tokens []string) {
	t.Helper()
	rows, err := a.db.Query(`SELECT to_email, url FROM outbox ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var e, u string
		if err := rows.Scan(&e, &u); err != nil {
			t.Fatal(err)
		}
		parsed, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		to = append(to, e)
		tokens = append(tokens, parsed.Query().Get("token"))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return to, tokens
}

func (a *app) count(t *testing.T, table string) int {
	t.Helper()
	var n int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (a *app) signIn(t *testing.T, email string) magiclink.Session {
	t.Helper()
	ctx := context.Background()
	if err := a.auth.SendLink(ctx, email, "1.2.3.4", nil); err != nil {
		t.Fatal(err)
	}
	_, tokens := a.outbox(t)
	s, _, err := a.auth.Verify(ctx, tokens[len(tokens)-1], "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignInRoundTrip(t *testing.T) {
	a := newApp(t)
	ctx := context.Background()

	if err := a.auth.SendLink(ctx, "  Amy@Example.COM ", "1.2.3.4", nil); err != nil {
		t.Fatal(err)
	}
	to, tokens := a.outbox(t)
	if len(to) != 1 || to[0] != "amy@example.com" {
		t.Fatalf("outbox = %v, want one email to amy@example.com", to)
	}
	if a.woken != 1 {
		t.Fatalf("AfterSend ran %d times, want 1", a.woken)
	}
	var u string
	_ = a.db.QueryRow(`SELECT url FROM outbox`).Scan(&u)
	if !strings.HasPrefix(u, "https://app.example.com/auth/verify?") || !strings.Contains(u, "from=email") {
		t.Fatalf("link URL = %q, want LinkURL with its query kept", u)
	}

	s, _, err := a.auth.Verify(ctx, tokens[0], "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if s.Email != "amy@example.com" || s.UserID == "" || s.Token == "" {
		t.Fatalf("session = %+v", s)
	}
	if want := a.now.Add(30 * 24 * time.Hour); !s.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want %v", s.ExpiresAt, want)
	}

	got, err := a.auth.Authenticate(ctx, s.Token)
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != s.UserID || got.Email != s.Email {
		t.Fatalf("Authenticate = %+v, want %+v", got, s)
	}

	if err := a.auth.SignOut(ctx, s.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := a.auth.Authenticate(ctx, s.Token); !errors.Is(err, magiclink.ErrUnauthorized) {
		t.Fatalf("after sign-out: err = %v, want ErrUnauthorized", err)
	}
}

func TestOnlyHashesAreStored(t *testing.T) {
	a := newApp(t)
	s := a.signIn(t, "amy@example.com")
	_, tokens := a.outbox(t)
	_ = a.auth.SendLink(context.Background(), "amy@example.com", "1.2.3.4", nil) // leave one link stored
	for _, tok := range []string{s.Token, tokens[0]} {
		var n int
		if err := a.db.QueryRow(`
			SELECT (SELECT COUNT(*) FROM magiclink_links WHERE instr(CAST(token_hash AS TEXT), ?) > 0) +
			       (SELECT COUNT(*) FROM magiclink_sessions WHERE instr(CAST(token_hash AS TEXT), ?) > 0)`,
			tok, tok).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("raw token found in the database")
		}
	}
}

func TestLinksAreSingleUse(t *testing.T) {
	a := newApp(t)
	ctx := context.Background()
	_ = a.auth.SendLink(ctx, "amy@example.com", "1.2.3.4", nil)
	_, tokens := a.outbox(t)
	if _, _, err := a.auth.Verify(ctx, tokens[0], "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.auth.Verify(ctx, tokens[0], "1.2.3.4"); !errors.Is(err, magiclink.ErrInvalidLink) {
		t.Fatalf("second use: err = %v, want ErrInvalidLink", err)
	}
}

func TestLinksExpire(t *testing.T) {
	a := newApp(t, func(c *magiclink.Config) { c.LinkTTL = 10 * time.Minute })
	ctx := context.Background()
	_ = a.auth.SendLink(ctx, "amy@example.com", "1.2.3.4", nil)
	_, tokens := a.outbox(t)
	a.now = a.now.Add(10 * time.Minute)
	if _, _, err := a.auth.Verify(ctx, tokens[0], "1.2.3.4"); !errors.Is(err, magiclink.ErrInvalidLink) {
		t.Fatalf("expired: err = %v, want ErrInvalidLink", err)
	}
}

func TestSessionsExpire(t *testing.T) {
	a := newApp(t, func(c *magiclink.Config) { c.SessionTTL = time.Hour })
	s := a.signIn(t, "amy@example.com")
	a.now = a.now.Add(time.Hour)
	if _, err := a.auth.Authenticate(context.Background(), s.Token); !errors.Is(err, magiclink.ErrUnauthorized) {
		t.Fatalf("expired: err = %v, want ErrUnauthorized", err)
	}
}

func TestDisallowedAddressLooksTheSameButNothingIsKept(t *testing.T) {
	a := newApp(t)
	if err := a.auth.SendLink(context.Background(), "eve@example.com", "1.2.3.4", nil); err != nil {
		t.Fatalf("err = %v, want nil (must not reveal the allowlist)", err)
	}
	if n := a.count(t, "outbox"); n != 0 {
		t.Fatalf("outbox has %d emails, want 0", n)
	}
	if n := a.count(t, "magiclink_links"); n != 0 {
		t.Fatalf("%d links stored, want 0", n)
	}
	if a.woken != 0 {
		t.Fatalf("AfterSend ran for a disallowed address")
	}
}

func TestSendErrorsReachTheCallerEitherWay(t *testing.T) {
	a := newApp(t)
	errBudget := errors.New("budget spent")
	a.sendErr = errBudget
	for _, email := range []string{"amy@example.com", "eve@example.com"} {
		if err := a.auth.SendLink(context.Background(), email, "1.2.3.4", nil); !errors.Is(err, errBudget) {
			t.Fatalf("%s: err = %v, want the Send error", email, err)
		}
	}
	if n := a.count(t, "magiclink_links"); n != 0 {
		t.Fatalf("%d links stored after a failed send, want 0", n)
	}
	if a.woken != 0 {
		t.Fatalf("AfterSend ran after a failed send")
	}
}

func TestFailedSignInLeavesTheLinkUsable(t *testing.T) {
	a := newApp(t)
	ctx := context.Background()
	_ = a.auth.SendLink(ctx, "amy@example.com", "1.2.3.4", nil)
	_, tokens := a.outbox(t)

	errClosed := errors.New("registration closed")
	a.signInErr = errClosed
	if _, _, err := a.auth.Verify(ctx, tokens[0], "1.2.3.4"); !errors.Is(err, errClosed) {
		t.Fatalf("err = %v, want the SignIn error", err)
	}
	if n := a.count(t, "magiclink_sessions"); n != 0 {
		t.Fatalf("%d sessions after a failed sign-in, want 0", n)
	}
	a.signInErr = nil
	if _, _, err := a.auth.Verify(ctx, tokens[0], "1.2.3.4"); err != nil {
		t.Fatalf("retry: %v", err)
	}
}

func TestStateIsCarriedToEveryHookAndBack(t *testing.T) {
	type join struct {
		Group int    `json:"group"`
		Name  string `json:"name"`
	}
	var allowState, sendState, signInState json.RawMessage
	a := newApp(t, func(c *magiclink.Config) {
		allow, send, signIn := c.Allow, c.Send, c.SignIn
		c.Allow = func(ctx context.Context, tx *sql.Tx, l magiclink.Link) (bool, error) {
			allowState = l.State
			if l.URL != "" {
				t.Error("Allow was given the link URL")
			}
			return allow(ctx, tx, l)
		}
		c.Send = func(ctx context.Context, tx *sql.Tx, l magiclink.Link) error {
			sendState = l.State
			return send(ctx, tx, l)
		}
		c.SignIn = func(ctx context.Context, tx *sql.Tx, l magiclink.Link) (string, error) {
			signInState = l.State
			return signIn(ctx, tx, l)
		}
	})
	ctx := context.Background()
	if err := a.auth.SendLink(ctx, "amy@example.com", "1.2.3.4", join{Group: 7, Name: "Amy"}); err != nil {
		t.Fatal(err)
	}
	_, tokens := a.outbox(t)
	_, link, err := a.auth.Verify(ctx, tokens[0], "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]json.RawMessage{
		"Allow": allowState, "Send": sendState, "SignIn": signInState, "Verify": link.State,
	} {
		var j join
		if err := json.Unmarshal(raw, &j); err != nil || j != (join{7, "Amy"}) {
			t.Errorf("%s saw state %s, want the join", name, raw)
		}
	}

	// Without state, hooks see nil.
	_ = a.auth.SendLink(ctx, "amy@example.com", "1.2.3.5", nil)
	_, tokens = a.outbox(t)
	_, link, err = a.auth.Verify(ctx, tokens[1], "1.2.3.5")
	if err != nil {
		t.Fatal(err)
	}
	if link.State != nil {
		t.Fatalf("state = %s, want nil", link.State)
	}
}

func TestLinkRequestsAreRateLimited(t *testing.T) {
	a := newApp(t, func(c *magiclink.Config) {
		c.Limits = magiclink.Limits{LinksPerIPPerHour: 5, LinksPerEmailPer15Min: 2, LinksPerEmailPerDay: 3}
	})
	ctx := context.Background()
	send := func(email, ip string) error { return a.auth.SendLink(ctx, email, ip, nil) }

	// Per address, from different IPs; the same for unknown addresses.
	for _, email := range []string{"amy@example.com", "eve@example.com"} {
		for i, ip := range []string{"10.0.0.1", "10.0.0.2"} {
			if err := send(email, ip); err != nil {
				t.Fatalf("%s #%d: %v", email, i, err)
			}
		}
		if err := send(email, "10.0.0.3"); !errors.Is(err, magiclink.ErrRateLimited) {
			t.Fatalf("%s 3rd in 15 min: err = %v, want ErrRateLimited", email, err)
		}
	}
	// The refused request didn't count: after 15 minutes one more is allowed,
	// then the daily limit (3) applies.
	a.now = a.now.Add(15 * time.Minute)
	if err := send("amy@example.com", "10.0.0.4"); err != nil {
		t.Fatal(err)
	}
	a.now = a.now.Add(15 * time.Minute)
	if err := send("amy@example.com", "10.0.0.4"); !errors.Is(err, magiclink.ErrRateLimited) {
		t.Fatalf("4th in a day: err = %v, want ErrRateLimited", err)
	}

	// Per IP.
	for i := range 5 {
		if err := send("user"+string(rune('a'+i))+"@example.com", "10.9.9.9"); err != nil {
			t.Fatalf("ip #%d: %v", i, err)
		}
	}
	if err := send("other@example.com", "10.9.9.9"); !errors.Is(err, magiclink.ErrRateLimited) {
		t.Fatalf("6th from one IP: err = %v, want ErrRateLimited", err)
	}
}

func TestVerifiesAreRateLimited(t *testing.T) {
	a := newApp(t, func(c *magiclink.Config) { c.Limits.VerifiesPerIPPerHour = 2 })
	ctx := context.Background()
	bogus := strings.Repeat("x", 43)
	for range 2 {
		if _, _, err := a.auth.Verify(ctx, bogus, "1.2.3.4"); !errors.Is(err, magiclink.ErrInvalidLink) {
			t.Fatalf("err = %v, want ErrInvalidLink", err)
		}
	}
	if _, _, err := a.auth.Verify(ctx, bogus, "1.2.3.4"); !errors.Is(err, magiclink.ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
}

func TestMalformedTokensNeverReachTheDatabase(t *testing.T) {
	a := newApp(t, func(c *magiclink.Config) { c.Limits.VerifiesPerIPPerHour = 1 })
	ctx := context.Background()
	for _, tok := range []string{"", "short", strings.Repeat("a", 10_000)} {
		if _, _, err := a.auth.Verify(ctx, tok, "1.2.3.4"); !errors.Is(err, magiclink.ErrInvalidLink) {
			t.Fatalf("Verify(%.10q) err = %v, want ErrInvalidLink (and no rate-limit hit)", tok, err)
		}
		if _, err := a.auth.Authenticate(ctx, tok); !errors.Is(err, magiclink.ErrUnauthorized) {
			t.Fatalf("Authenticate(%.10q) err = %v, want ErrUnauthorized", tok, err)
		}
		if err := a.auth.SignOut(ctx, tok); err != nil {
			t.Fatalf("SignOut(%.10q) err = %v", tok, err)
		}
	}
}

func TestSignOutUserEndsAllTheirSessions(t *testing.T) {
	a := newApp(t)
	a.allowed["bob@example.com"] = true
	ctx := context.Background()
	s1 := a.signIn(t, "amy@example.com")
	s2 := a.signIn(t, "amy@example.com")
	bob := a.signIn(t, "bob@example.com")
	if s1.UserID != s2.UserID {
		t.Fatalf("two sign-ins gave different users")
	}
	if err := a.auth.SignOutUser(ctx, s1.UserID); err != nil {
		t.Fatal(err)
	}
	for _, s := range []magiclink.Session{s1, s2} {
		if _, err := a.auth.Authenticate(ctx, s.Token); !errors.Is(err, magiclink.ErrUnauthorized) {
			t.Fatalf("err = %v, want ErrUnauthorized", err)
		}
	}
	if _, err := a.auth.Authenticate(ctx, bob.Token); err != nil {
		t.Fatalf("other user's session ended: %v", err)
	}
}

func TestExpiredRowsArePrunedAsItGoes(t *testing.T) {
	a := newApp(t, func(c *magiclink.Config) { c.SessionTTL = time.Hour })
	ctx := context.Background()
	a.signIn(t, "amy@example.com")
	_ = a.auth.SendLink(ctx, "amy@example.com", "1.2.3.4", nil) // left unused

	a.now = a.now.Add(2 * time.Hour)
	a.signIn(t, "amy@example.com")
	if n := a.count(t, "magiclink_links"); n != 0 {
		t.Fatalf("%d links left, want the expired one pruned", n)
	}
	if n := a.count(t, "magiclink_sessions"); n != 1 {
		t.Fatalf("%d sessions, want only the live one", n)
	}
}

func TestNewChecksConfig(t *testing.T) {
	db, _ := sql.Open("sqlite", ":memory:")
	defer func() { _ = db.Close() }()
	ok := magiclink.Config{
		DB: db, LinkURL: "https://x.example/v",
		Send:   func(context.Context, *sql.Tx, magiclink.Link) error { return nil },
		SignIn: func(context.Context, *sql.Tx, magiclink.Link) (string, error) { return "1", nil },
	}
	if _, err := magiclink.New(context.Background(), ok); err != nil {
		t.Fatal(err)
	}
	// New is idempotent: tables already exist.
	if _, err := magiclink.New(context.Background(), ok); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*magiclink.Config){
		"no DB":           func(c *magiclink.Config) { c.DB = nil },
		"no Send":         func(c *magiclink.Config) { c.Send = nil },
		"no SignIn":       func(c *magiclink.Config) { c.SignIn = nil },
		"relative URL":    func(c *magiclink.Config) { c.LinkURL = "/auth/verify" },
		"missing LinkURL": func(c *magiclink.Config) { c.LinkURL = "" },
	} {
		c := ok
		mutate(&c)
		if _, err := magiclink.New(context.Background(), c); err == nil {
			t.Errorf("%s: New succeeded", name)
		}
	}
}

func TestEmptyUserIDIsRefused(t *testing.T) {
	a := newApp(t, func(c *magiclink.Config) {
		c.SignIn = func(context.Context, *sql.Tx, magiclink.Link) (string, error) { return "", nil }
	})
	ctx := context.Background()
	_ = a.auth.SendLink(ctx, "amy@example.com", "1.2.3.4", nil)
	_, tokens := a.outbox(t)
	if _, _, err := a.auth.Verify(ctx, tokens[0], "1.2.3.4"); err == nil {
		t.Fatal("Verify accepted an empty user ID")
	}
	if n := a.count(t, "magiclink_sessions"); n != 0 {
		t.Fatalf("%d sessions created, want 0", n)
	}
}

func TestUUIDUserIDs(t *testing.T) {
	const id = "0b8f8d6e-5c1a-4c47-9a4e-2f3d6f0e7a11"
	a := newApp(t, func(c *magiclink.Config) {
		c.SignIn = func(context.Context, *sql.Tx, magiclink.Link) (string, error) { return id, nil }
	})
	s := a.signIn(t, "amy@example.com")
	got, err := a.auth.Authenticate(context.Background(), s.Token)
	if err != nil || got.UserID != id {
		t.Fatalf("Authenticate = %+v, %v; want user %s", got, err, id)
	}
}

// A database made by v0.1.0 (integer user IDs, no magiclink_schema) is
// upgraded in place, and its sessions keep working.
func TestUpgradeFromV010KeepsSessions(t *testing.T) {
	db, err := sql.Open("sqlite", "file::memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer func() { _ = db.Close() }()
	now := time.Unix(1_800_000_000, 0)
	token := strings.Repeat("A", 43) // a well-formed token; only its hash is stored
	if _, err := db.Exec(`
		CREATE TABLE magiclink_links (token_hash BLOB PRIMARY KEY, email TEXT NOT NULL, state TEXT, expires_at INTEGER NOT NULL) STRICT;
		CREATE INDEX magiclink_links_expires ON magiclink_links (expires_at);
		CREATE TABLE magiclink_sessions (token_hash BLOB PRIMARY KEY, user_id INTEGER NOT NULL, email TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL) STRICT;
		CREATE INDEX magiclink_sessions_expires ON magiclink_sessions (expires_at);
		CREATE INDEX magiclink_sessions_user ON magiclink_sessions (user_id);`); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(token))
	if _, err := db.Exec(`INSERT INTO magiclink_sessions VALUES (?, 42, 'amy@example.com', ?, ?)`,
		h[:], now.Unix(), now.Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	cfg := magiclink.Config{
		DB: db, LinkURL: "https://x.example/v", Now: func() time.Time { return now },
		Send:   func(context.Context, *sql.Tx, magiclink.Link) error { return nil },
		SignIn: func(context.Context, *sql.Tx, magiclink.Link) (string, error) { return "1", nil },
	}
	for range 2 { // the second New must be a no-op
		auth, err := magiclink.New(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		s, err := auth.Authenticate(context.Background(), token)
		if err != nil || s.UserID != "42" || s.Email != "amy@example.com" {
			t.Fatalf("Authenticate after upgrade = %+v, %v; want user 42", s, err)
		}
	}
	var typ string
	if err := db.QueryRow(`SELECT type FROM pragma_table_info('magiclink_sessions') WHERE name = 'user_id'`).Scan(&typ); err != nil || typ != "TEXT" {
		t.Fatalf("user_id column type = %q (%v), want TEXT", typ, err)
	}
}
