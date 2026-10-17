# @shrug/managesieve

Provider-agnostic ManageSieve (RFC 5804) client for swamp. Pairs with
`@shrug/imap` (read snapshot) and `@shrug/mail-ontology` (classify +
propose) in a swamp-managed mail toolchain, then lets a mailbox's
server-side Sieve filters be inspected and (behind a dry-run gate) managed
declaratively.

No third-party ManageSieve client exists on npm with any real maintenance
signal (checked at build time: no hits for `managesieve`, `node-sieve`,
`sieve-connect`, `node-managesieve`, `managesieve-client`). The protocol itself
is a small IMAP-family line protocol, so it is implemented directly on top of
Deno's native `Deno.connect`/`Deno.startTls` -- zero npm dependencies, zero
supply-chain risk. All wire I/O goes through a single injectable transport
seam (`SieveTransport`), so unit tests run against a synthetic scripted
transport and never touch a live server.

## Methods

Read-only:

- `listScripts` -- LISTSCRIPTS. Returns `{name, active}[]`.
- `getScript(name)` -- GETSCRIPT. Returns the raw script text as a snapshot
  resource.
- `getActive` -- derived from LISTSCRIPTS. Returns the active script name, or
  `null`.
- `checkScript(text)` -- CHECKSCRIPT. Validates a script against the server's
  Sieve interpreter *without* installing it. Returns `{ok, errors[]}`.

Gated writes (dryRun defaults to `true`; `dryRun=false` is the only mutate
path):

- `putScript(name, text)` -- CHECKSCRIPT first (always, regardless of
  `dryRun`), then PUTSCRIPT. Refuses to mutate if CHECKSCRIPT fails. Idempotent:
  a byte-identical live script is a recorded no-op.
- `setActive(name)` -- SETACTIVE. `name=""` deactivates. Idempotent: activating
  (or deactivating) the already-active script is a no-op. Refuses to activate
  a name that is not in the LISTSCRIPTS set.
- `deleteScript(name)` -- DELETESCRIPT. **Refuses to delete the currently
  active script** (verify-before-destructive). Idempotent: deleting a script
  that no longer exists is a recorded no-op, not an error.

## Why RFC 5804 literals, always

Every ManageSieve `string`-typed command argument (script name, script text,
the SASL initial response) is sent using the protocol's non-synchronizing
client literal form, `{n+}\r\n<n raw bytes>`, never a quoted string. A literal
is purely length-prefixed: the server reads exactly `n` bytes no matter what
they contain (CRLF, quotes, braces, anything), so a hostile or just
awkward script name/body can never be parsed as a second command or break out
of its argument position. This is the single place command framing is
constructed (`encodeLiteral` / `buildCommandBytes` in `managesieve.ts`) and is
the most heavily unit-tested surface in this model.

## Example: dry-run preview before a live write

Every write method defaults `dryRun` to `true`, so running it with no
`dryRun` argument is always a safe preview -- it opens the connection, runs
LISTSCRIPTS/GETSCRIPT/CHECKSCRIPT (all read-only RFC commands) to compute
what would happen, and writes a `wouldAffect` resource with zero mutation:

```bash
swamp model @shrug/managesieve method run putScript sieve-sandbox \
  --arg name=cleanup --arg text="$(cat ./cleanup.sieve)"
# -> wouldAffect: { before: null, after: "<script text>", changed: true,
#                   checkResult: { ok: true, errors: [], warnings: [] },
#                   refused: null, dryRun: true }
```

Only `--arg dryRun=false` performs the PUTSCRIPT (and only after CHECKSCRIPT
has already passed in the same call).

## Configuration

Global arguments:

| Field                   | Required | Default | Notes                                                                    |
| ------------------------ | -------- | ------- | ------------------------------------------------------------------------- |
| `host`                   | yes      | --      | ManageSieve server hostname, e.g. sieve.example.com                     |
| `port`                   | no       | `4190`  | ManageSieve port per RFC 5804                                            |
| `user`                   | yes      | --      | Mailbox login, e.g. user@example.com                                    |
| `password`               | yes      | --      | Sensitive; resolve from a vault via CEL                                 |
| `tlsRejectUnauthorized`  | no       | `true`  | See TLS note below                                                       |
| `allowInsecure`          | no       | `false` | Must be true to authenticate without a successful STARTTLS upgrade      |

```
password: ${{ vault.get("my-mailbox", "password") }}
```

### TLS note

Deno's stable TLS API always validates the full certificate chain; there is no
stable, per-connection way to disable chain validation (unlike Node's
`rejectUnauthorized: false`). `tlsRejectUnauthorized: false` maps to
`Deno.startTls`'s `unsafelyDisableHostnameVerification` -- it only relaxes the
hostname check, the chain is still validated. Leave it `true` in normal
deployments.

## Scope

This model only talks to the ManageSieve *control* protocol (manage scripts).
It does not compile mail-classification rules into Sieve source -- that
compilation step, and wiring a model instance to a live server, are
follow-on work. No live server is contacted by this build; every test runs
against a synthetic transport.
