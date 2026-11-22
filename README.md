# go-magic-links

Passwordless sign-in for Go apps on SQLite: emailed single-use links plus
opaque session tokens. Used by `timer` and `secret-gift-exchange`.

```go
import magiclink "github.com/tkightly/go-magic-links"
```

## Usage

```go
auth, err := magiclink.New(ctx, magiclink.Config{
	DB:      db,                                   // *sql.DB (SQLite)
	LinkURL: "https://app.example.com/auth/verify", // ?token=… is added

	// Who may be sent a link. Nil allows everyone.
	Allow: func(ctx context.Context, tx *sql.Tx, l magiclink.Link) (bool, error) {
		return allowlist[l.Email], nil
	},
	// Queue the email through tx (an outbox), never send directly.
	Send: func(ctx context.Context, tx *sql.Tx, l magiclink.Link) error {
		return enqueue(ctx, tx, l.Email, "magic_link", l.URL, l.ExpiresAt)
	},
	// Wake the outbox worker once the email is committed.
	AfterSend: worker.Wake,
	// Map a verified email to your user ID (create the user on first sign-in).
	SignIn: func(ctx context.Context, tx *sql.Tx, l magiclink.Link) (int64, error) {
		return upsertUser(ctx, tx, l.Email)
	},
})

// POST /auth/link — always answer the same way, whether or not the address may sign in.
err = auth.SendLink(ctx, email, clientIP, nil)

// POST /auth/verify
session, link, err := auth.Verify(ctx, token, clientIP)  // session.Token goes in a cookie

// Every authenticated request
session, err := auth.Authenticate(ctx, token)            // session.UserID, session.Email

auth.SignOut(ctx, token)          // one session
auth.SignOutUser(ctx, userID)     // all of a user's sessions, e.g. access revoked
```

Errors: `ErrInvalidLink`, `ErrUnauthorized` and `ErrRateLimited`. Errors from
your hooks come back unchanged, so `errors.Is` works on your own error values.

### Carrying intent through a link

`SendLink`'s last argument is optional state. It is stored with the link as
JSON, handed to every hook as `Link.State` and returned from `Verify`. That
is how a "join this group" link works:

```go
auth.SendLink(ctx, email, ip, joinState{GroupID: 7, Name: "Amy"})

// in SignIn: if l.State != nil, unmarshal it and add the user to the group.
// After Verify: use link.State to choose where to redirect.
```

If `SignIn` returns an error (say registration has closed), the transaction
rolls back and the link stays unused.

## Design

The package is built as a *deep module*, in the sense used in *A Philosophy
of Software Design*: a small interface (five methods, three errors and one
config struct) in front of a lot of behaviour that callers no longer need to
know about.

**What it hides** (both apps used to implement each of these themselves):

| Concern | Detail callers no longer see |
|---|---|
| Tokens | 256-bit random, base64url. Only SHA-256 hashes are stored, so a leaked database can't be used to sign in. |
| Malformed input | Wrong-length tokens are rejected before any database query or rate-limit hit. |
| Single use | Claiming a link deletes it in the same transaction that creates the session. |
| Expiry | Links (15 min) and sessions (30 days) can be configured. |
| Housekeeping | Expired links and sessions are pruned as part of normal calls, so there is no `Cleanup` to schedule. |
| Rate limits | Per IP, per address per 15 min and per day on link requests, and per IP on verifications. Every limit is checked before any is recorded, so a refused request doesn't use up the others. |
| Not revealing who can sign in | For a disallowed address the module does the same work (insert, `Send`) and then rolls back. The response, the timing and any `Send` error are the same either way, and limits apply to every address alike. |
| Email normalisation | Addresses are trimmed and lower-cased before any hook sees them. |
| Schema | Its own `magiclink_links` and `magiclink_sessions` tables, created by `New`. |

**What stays with the app** is policy that really differs between apps,
passed in through hooks rather than options:

- **`Allow`**: timer checks an allowlist. secret-gift-exchange allows
  organisers and people it already knows, plus anyone holding a join link.
- **`Send`**: each app has its own outbox, templates and daily email budget.
- **`SignIn`**: each app owns its `users` table. timer creates default
  settings for new users; secret-gift-exchange also adds the person to an
  exchange.

The hooks run inside the module's transaction and receive its `*sql.Tx`, so
user creation, joining and email queueing commit or roll back together with
the link and the session. Hooks must only use that `tx`: the apps run a
one-connection pool, so touching `DB` inside a hook would deadlock.

**Choices that keep the interface small:**

- The module never sees the user table. `SignIn` returns an `int64`, which
  is stored on the session and handed back by `Authenticate`. That avoids a
  second query per request without the module owning users.
- It has no HTTP layer. The two apps' JSON shapes, error bodies and
  client-IP rules differ, and an HTTP adapter would mostly be options. The
  HTTP handlers that remain in each app are about ten lines each.
- Rate limits are inside the module, not left to callers, because the
  ordering rules that prevent leaks are easy to get wrong. The only cost is
  passing a `clientIP` string.
- There is no "re-check access on every request" option. timer does that in
  three lines with `SignOutUser`. secret-gift-exchange doesn't need it.

## Requirements

- SQLite through `database/sql`; tested with `modernc.org/sqlite`. The SQL
  uses `STRICT` tables and `RETURNING`.
- Rate limits are kept in memory, so they suit a single API instance and
  reset on restart.
