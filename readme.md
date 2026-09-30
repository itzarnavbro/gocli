# gocli: containerized CLI login system with optional 2FA

An interactive command-line login system written in Go. It supports registration,
password login, optional TOTP two-factor authentication (Google Authenticator
compatible), account lockout and expiring sessions. It runs in Docker with SQLite
data persisted in a volume.

The code is deliberately stdlib-heavy. TOTP (RFC 4226 / RFC 6238), PHC hash
encoding and the AES-GCM helpers are implemented here rather than pulled from libraries.
The only dependencies are `golang.org/x/crypto` (Argon2id), `golang.org/x/term`
(raw terminal) and `modernc.org/sqlite` (pure-Go SQLite driver).

## Quick start (Docker)

Requirements: Docker with Compose.

```bash
# 1. create the encryption key for stored 2FA secrets (64 hex chars)
echo "TOTP_ENC_KEY=$(openssl rand -hex 32)" > .env

# 2. build and start the interactive prompt
docker compose build
docker compose run --rm app
```

PowerShell equivalent for step 1:

```powershell
$b = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
"TOTP_ENC_KEY=$(($b | ForEach-Object { $_.ToString('x2') }) -join '')" | Set-Content .env -Encoding ascii
```

Notes:

- Use `docker compose run`, not `up`. The CLI needs an interactive terminal.
- Use PowerShell, Windows Terminal or a normal Linux/macOS terminal. Some
  Windows shells (for example Git Bash) are not real terminals to Go, so the
  program falls back to a plain line reader (no tab-completion, passwords are echoed)
  and prints a warning.
- Keep the `.env` file. If `TOTP_ENC_KEY` changes, users with 2FA enabled can no
  longer log in, because their stored secrets can't be decrypted.

## Commands

Before login:

| Command    | Description                                        |
|------------|----------------------------------------------------|
| `register` | create an account                                  |
| `login`    | log in with username and password (+ 2FA if on)    |
| `help`     | list the commands available right now              |
| `exit`     | quit                                               |

After login:

| Command       | Description                              |
|---------------|------------------------------------------|
| `whoami`      | show your user details                   |
| `enable-2fa`  | set up TOTP two-factor authentication    |
| `disable-2fa` | turn 2FA off (needs password and code)   |
| `logout`      | end the session                          |
| `help`        | list the commands available right now    |

Usability: Tab completes command names (only those available in the current
state), Up/Down recalls history (history never contains usernames, passwords or
codes), passwords are masked, and Ctrl+D inside a prompt cancels that command.
After login (and with `whoami`) the program shows username, registration date, 2FA status,
session expiry and last login time.

### Enabling 2FA

1. Run `enable-2fa`. The program prints a setup key and an `otpauth://` URI.
2. In Google Authenticator choose **+ > Enter a setup key**, type the account name and
   key, and keep "Time based" selected.
3. Enter the 6-digit code from the app to confirm. 2FA only turns on once a valid code
   is entered.

## Configuration

Environment variables (set in `.env` or `docker-compose.yml`):

| Variable              | Default          | Meaning                                         |
|-----------------------|------------------|-------------------------------------------------|
| `TOTP_ENC_KEY`        | (required)       | 64 hex chars (32 bytes), encrypts 2FA secrets   |
| `SESSION_TTL`         | `15m`            | session lifetime                                |
| `MAX_FAILED_ATTEMPTS` | `5`              | failures before lockout                         |
| `LOCKOUT_DURATION`    | `15m`            | how long an account stays locked                |
| `TOTP_ISSUER`         | `CLI-Login`      | name shown in the authenticator app             |
| `DB_PATH`             | `/data/app.db`   | SQLite file (the `data` volume in Docker)       |

## Persistence

The SQLite file lives on the named volume `data`, mounted at `/data`.

```bash
docker compose run --rm app     # register, then exit
docker compose down             # removes containers, keeps the volume
docker compose run --rm app     # the user is still there
docker compose down -v          # WARNING: also deletes the volume (all users)
```

## Database schema and migrations

SQL migrations are in `internal/db/migrations/` and are embedded in the binary.
They are applied automatically on startup and tracked in a `schema_migrations`
table, so restarts are idempotent. To change the schema, add `002_xxx.sql`.

Tables: `users` (credentials, 2FA state, lockout counters, timestamps) and
`sessions` (hashed token, expiry).

## Security design

- **Passwords:** Argon2id (64 MiB, 3 iterations, 2 lanes, random 16-byte salt), stored
  as a PHC string. Hashes made with weaker parameters are upgraded automatically on
  the next successful login. Verification is constant-time. Hashing takes roughly
  80 ms on the author's laptop (`go test -bench` in `internal/password`).
- **User enumeration:** an unknown username and a wrong password return the same
  error and take similar time (a dummy hash is verified for unknown users).
- **Lockout:** after `MAX_FAILED_ATTEMPTS` failures the account is locked for
  `LOCKOUT_DURATION`. The counter is one atomic SQL `UPDATE ... RETURNING`, so
  concurrent attempts can't be lost (covered by a concurrency test). Wrong 2FA codes
  and wrong answers in `disable-2fa` count as failures too.
- **Sessions:** a token is 256 random bits. Only its SHA-256 is stored, so a leaked database
  does not contain usable tokens. Expiry is absolute (`SESSION_TTL`) and is checked
  before every command. A background goroutine deletes expired sessions.
- **TOTP:** implemented from RFC 4226/6238 and tested against the official vectors.
  Codes within one 30 s step either side are accepted (clock drift). A used step is
  never accepted again (replay protection). Comparisons are constant-time.
- **2FA secrets at rest:** encrypted with AES-256-GCM, with the user id as
  authenticated data, so a secret copied into another user's row won't decrypt.
  Enabling 2FA needs a valid code, and disabling it needs the password and a code.
- **Container:** multi-stage build, static binary, distroless image with no shell,
  runs as a non-root user.

## Tests

```bash
go vet ./...
go test ./...                              # unit + integration tests
go test -cover ./...                       # coverage
docker compose --profile test run --rm test   # tests with the race detector (Linux)
```

What is covered: RFC test vectors, hash format, rehash and malformed input
(including a fuzz test), lockout and session expiry using a fake clock,
TOTP replay, 2FA enable/disable, one shared test suite that runs against both the
SQLite store and an in-memory store, concurrent failure counting, scripted CLI
sessions, and persistence across a simulated restart. The raw-terminal code can't
run under `go test`, so the CLI package has lower coverage.

## Project layout

```
cmd/app/                 entry point: config, database, shell, graceful shutdown
internal/config/         environment configuration
internal/db/             SQLite open + embedded migrations
internal/domain/         types, Store and Clock interfaces, errors
internal/otp/            HOTP / TOTP (RFC 4226 / 6238)
internal/password/       Argon2id hashing, PHC encoding, password policy
internal/store/          SQLite store and in-memory test store
internal/auth/           register, login, sessions, 2FA, lockout
internal/cli/            command registry, shell loop, terminal I/O
```

## Design decisions

- **`Clock` and `Store` interfaces.** Time and storage are injected, so lockout,
  expiry and TOTP windows are tested deterministically without sleeping.
- **Command registry.** Each command is one struct. `help`, tab-completion and the
  before/after-login rules are all generated from that table.
- **Errors as values.** Sentinel and typed errors (`errors.Is` / `errors.As`) are
  mapped to user messages in one place. Unexpected errors are logged and the
  user sees a generic message.
- **SQLite with a single connection.** It removes write contention and keeps the
  design simple for a single-user CLI.

## Limitations

- Passwords are Go strings and can't be reliably wiped from memory.
- No backup or recovery codes: a user who loses their authenticator can't log in.
- The terminal shows the setup key and URI but no QR code.
- The lock check comes before the password check, so someone who knows a username can
  lock that account. The alternative would let attackers keep guessing while it is locked.
- Registration reveals whether a username is taken.
- Sessions live in the process that created them (the token is held in memory).
- SQLite suits a single container. For several instances you would switch to PostgreSQL.