/**
 * Provider-agnostic ManageSieve (RFC 5804) client model.
 *
 * No maintained ManageSieve client exists on npm (checked at build time: zero
 * hits for `managesieve`, `node-sieve`, `sieve-connect`, `node-managesieve`,
 * `managesieve-client` on the npm registry/search API). The protocol is a
 * small, well-specified IMAP-family line protocol, so it is implemented
 * directly on Deno's native `Deno.connect`/`Deno.startTls` primitives --
 * zero npm dependencies, zero supply-chain risk, zero bundler pinning
 * concerns. This is NOT a shell/CLI wrapper: every byte on the wire goes
 * through a single injectable transport seam ({@link SieveTransport}), so
 * unit tests run against a synthetic scripted transport and no live server
 * is ever contacted during a build.
 *
 * ## Protocol summary (RFC 5804)
 *
 * On connect the server sends a greeting: zero or more `"NAME" ["value"]`
 * capability lines followed by a terminal OK. If the server advertises
 * STARTTLS, the client issues `STARTTLS`, reads the single OK response for
 * that command, upgrades the connection in place, and the server re-issues
 * its capabilities (which the client MUST discard and replace -- this is the
 * man-in-the-middle protection the RFC requires). The client then
 * authenticates with `AUTHENTICATE "PLAIN" <base64 SASL PLAIN initial
 * response>` (the only mechanism this model implements, matching the RFC's
 * baseline requirement of PLAIN-over-TLS). Once authenticated, the
 * script-management commands (LISTSCRIPTS, GETSCRIPT, PUTSCRIPT, SETACTIVE,
 * DELETESCRIPT, CHECKSCRIPT) are available.
 *
 * ## Literal framing is the injection-safety boundary
 *
 * Every ManageSieve command argument that is grammar-typed `string` (script
 * name, script text, the SASL auth-type and initial response) is ALWAYS
 * sent using the protocol's client literal form -- `{n+}\r\n` followed by
 * exactly `n` raw bytes ({@link encodeLiteral}) -- never a quoted string.
 * A literal is purely length-prefixed: the server reads exactly `n` bytes
 * no matter what they contain (embedded CRLF, quotes, braces, anything), so
 * a hostile or merely awkward script name/body can never be parsed as a
 * second command or escape its argument position. {@link buildCommandBytes}
 * is the single place a command is assembled; {@link encodeLiteral} is the
 * single place a literal is framed. Both are exported and directly unit
 * tested with adversarial content (embedded `{0+}`, CRLF, quotes, a second
 * fake command) to prove the byte count and payload always round-trip
 * intact.
 *
 * ## STARTTLS plaintext-injection guard
 *
 * A classic bug class in STARTTLS clients: if a single TCP read happens to
 * deliver the legitimate "OK" response AND additional attacker-injected
 * plaintext bytes in the same segment, and the client's buffered line
 * reader carries those extra bytes forward into the post-upgrade read
 * stream, the injected plaintext is misread as trusted post-TLS protocol
 * data. {@link SieveTransport.startTls} (both the interface contract and
 * {@link defaultTransportFactory}'s implementation) discards any bytes
 * still buffered from the plaintext connection at the moment of upgrade --
 * only bytes read from the NEW TLS-wrapped connection are ever trusted
 * afterward.
 *
 * ## Read path (always safe)
 *
 *   - listScripts: LISTSCRIPTS -- `{name, active}[]`.
 *   - getScript: GETSCRIPT -- the raw script text as a snapshot resource.
 *   - getActive: derived from LISTSCRIPTS -- the active script name or null.
 *   - checkScript: CHECKSCRIPT -- validates a script against the server's
 *     Sieve interpreter WITHOUT installing it.
 *
 * ## Write path (gated)
 *
 *   - putScript: CHECKSCRIPTs the proposed text FIRST, unconditionally
 *     (even when `dryRun=true`, so the preview carries a real check
 *     result), then PUTSCRIPTs. Refuses to mutate if CHECKSCRIPT fails.
 *     Idempotent: a byte-identical live script is a recorded no-op (no
 *     PUTSCRIPT is ever sent for unchanged content).
 *   - setActive: SETACTIVE; `name=""` deactivates. Refuses to activate a
 *     name LISTSCRIPTS does not report. Idempotent: activating (or
 *     deactivating) the already-active state is a recorded no-op.
 *   - deleteScript: DELETESCRIPT. REFUSES to delete the currently active
 *     script (verify-before-destructive) -- deactivate it first via
 *     setActive. Idempotent: deleting a script that no longer exists is a
 *     recorded no-op, not an error.
 *
 * Every write method defaults `dryRun` to `true` in its zod schema.
 * `dryRun=true` performs ZERO server mutation (LISTSCRIPTS/GETSCRIPT/
 * CHECKSCRIPT are all read-only RFC commands) and computes a `wouldAffect`
 * preview, including a `refused` field when the business-rule guard
 * (CHECKSCRIPT failure, delete-active-script, activate-nonexistent) would
 * block the call -- previewing a refusal is itself useful information, so
 * `dryRun=true` never throws for these cases. `dryRun=false` is the sole
 * mutate path: it throws (no mutation) when `refused` is set, matching
 * "verify before destructive operations".
 *
 * ## Terminal vs. data lines are distinguished by FRAMING, not content
 *
 * A terminal response line (`response-ok`/`response-nobye`) begins with a
 * bare `OK`/`NO`/`BYE` atom. Every DATA line -- a LISTSCRIPTS sieve-name, a
 * GETSCRIPT script body -- is a grammar `string` (quoted, or a pure `{n}`
 * literal) and so never begins with that atom. {@link readLogicalLine}
 * therefore classifies each line as terminal-or-data from the HEAD line
 * alone, BEFORE resolving any literal, and the OK/NO/BYE grammar is matched
 * ONLY on lines framed as terminal -- never against literal payload bytes.
 * This is why a GETSCRIPT body whose text happens to start with
 * `ok`/`no`/`bye` is safe: it arrives as a literal data line, is flagged
 * non-terminal, and is returned verbatim rather than misparsed as a
 * response (which previously broke `cmdGetScript`, and in turn
 * `putScript`'s own before/after diff on the gated-write safety path).
 *
 * ## Resource exhaustion bounds (untrusted server)
 *
 * The client never trusts a server's self-reported sizes: a server-declared
 * literal octet count is rejected before allocation if it exceeds
 * {@link MAX_LITERAL_BYTES}, a response line that never terminates is
 * aborted once it passes {@link MAX_LINE_BYTES}, and every socket operation
 * (connect, TLS upgrade, each read, each write) is bounded by the
 * `timeoutMs` deadline so a server that accepts the connection then stalls
 * can never hang the method.
 *
 * @module
 */
import { z } from "npm:zod@4";

// ---------------------------------------------------------------------------
// Safety limits (DoS bounds for an untrusted server) + defaults
// ---------------------------------------------------------------------------

/**
 * Default per-operation deadline (ms) for connect / TLS upgrade / each
 * socket read / each socket write. Overridable via the `timeoutMs` global
 * argument; 0 disables it.
 */
export const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * Hard upper bound on a single server-declared literal ({n}) octet count,
 * checked BEFORE any allocation. A Sieve script is small; 1 MiB is already
 * far larger than any real script or error block. A server declaring a
 * larger (or non-finite) count is rejected rather than trusted, defeating
 * an unbounded-allocation / RangeError DoS (MS-2).
 */
export const MAX_LITERAL_BYTES = 1024 * 1024;

/**
 * Hard upper bound on how many bytes {@link LineReader.readLine} will buffer
 * while hunting for a line terminator. A server that streams forever with no
 * CRLF would otherwise grow the buffer without limit; past this cap the read
 * is aborted (MS-2). Comfortably larger than any legitimate greeting,
 * capability block line, or terminal response line.
 */
export const MAX_LINE_BYTES = 64 * 1024;

// ---------------------------------------------------------------------------
// Global arguments (connection + vaulted credential)
// ---------------------------------------------------------------------------

/** Connection and authentication settings for one ManageSieve mailbox. */
const GlobalArgsSchema = z.object({
  host: z
    .string()
    .min(1)
    .describe("ManageSieve server hostname, e.g. sieve.example.com"),
  port: z
    .number()
    .int()
    .min(1)
    .max(65535)
    .default(4190)
    .describe("ManageSieve server port (4190 per RFC 5804)"),
  user: z
    .string()
    .min(1)
    .describe("Mailbox login, e.g. user@example.com"),
  password: z
    .string()
    .meta({ sensitive: true })
    .describe(
      "Mailbox password/app-password. Resolve from a swamp vault via CEL; " +
        'e.g. ${{ vault.get("my-mailbox", "password") }}. Never inline it.',
    ),
  tlsRejectUnauthorized: z
    .boolean()
    .default(true)
    .describe(
      "Verify the server's TLS identity during STARTTLS. Deno's TLS stack " +
        "always validates the certificate CHAIN; this flag only controls " +
        "HOSTNAME verification (Deno.startTls's " +
        "unsafelyDisableHostnameVerification) -- there is no stable Deno API " +
        "to bypass chain validation entirely. Leave true in normal " +
        "deployments.",
    ),
  allowInsecure: z
    .boolean()
    .default(false)
    .describe(
      "Must be true to permit authenticating when the server does not " +
        "advertise STARTTLS. Guards against accidentally sending the " +
        "mailbox credential over a connection that was never upgraded to " +
        "TLS. Leave false in normal deployments.",
    ),
  timeoutMs: z
    .number()
    .int()
    .min(0)
    .default(DEFAULT_TIMEOUT_MS)
    .describe(
      "Per-operation deadline in milliseconds for connect, TLS upgrade, " +
        "each socket read, and each socket write. A server that accepts " +
        "the connection then stalls mid-response would otherwise hang the " +
        "method forever; on timeout the transport is closed and the method " +
        "throws. 0 disables the deadline (only for a known-good test/dev " +
        "server). Default " + DEFAULT_TIMEOUT_MS + " ms.",
    ),
});

/** Resolved connection and authentication settings. */
export type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

// ---------------------------------------------------------------------------
// Resource schemas
// ---------------------------------------------------------------------------

/** One script as reported by LISTSCRIPTS. */
const ScriptEntrySchema = z.object({
  name: z.string(),
  active: z.boolean(),
});

/** A script entry (plain object form, used internally and in resources). */
export type ScriptEntry = z.infer<typeof ScriptEntrySchema>;

/** The full set of scripts on the server. */
const ScriptListSchema = z.object({
  scripts: z.array(ScriptEntrySchema),
  count: z.number().int(),
  retrievedAt: z.iso.datetime(),
});

/** The raw contents of one script (GETSCRIPT). */
const ScriptContentSchema = z.object({
  name: z.string(),
  content: z.string(),
  size: z.number().int().describe("UTF-8 byte length of content"),
  retrievedAt: z.iso.datetime(),
});

/** The currently active script name, or null if none. */
const ActiveScriptSchema = z.object({
  name: z.string().nullable(),
  retrievedAt: z.iso.datetime(),
});

/** A CHECKSCRIPT (or pre-PUTSCRIPT) validation result. */
const CheckResultSchema = z.object({
  ok: z.boolean(),
  errors: z.array(z.string()),
  warnings: z.array(z.string()),
  code: z.string().nullable().describe("Server resp-code, e.g. WARNINGS"),
  retrievedAt: z.iso.datetime(),
});

/** The server's final tagged response to a mutate command. */
const ServerResponseSchema = z.object({
  tag: z.string(),
  code: z.string().nullable(),
  text: z.string().nullable(),
});

/**
 * A dryRun=true (the default) preview of a write method's effect. Emitted
 * instead of mutating anything -- dryRun=true performs ZERO server
 * mutation (every command used to compute the preview -- LISTSCRIPTS,
 * GETSCRIPT, CHECKSCRIPT -- is itself a read-only RFC command).
 */
const WouldAffectSchema = z.object({
  op: z.enum(["putScript", "setActive", "deleteScript"]),
  name: z.string().describe("The method's `name` argument, verbatim"),
  action: z.enum(["put", "activate", "deactivate", "delete"]),
  before: z.string().nullable().describe(
    "put/delete: existing script content, null if it doesn't exist yet. " +
      "activate/deactivate: the currently active script name, null if none.",
  ),
  after: z.string().nullable().describe(
    "put: the proposed new content. activate: the target script name. " +
      "deactivate/delete: always null.",
  ),
  changed: z.boolean().describe(
    "Whether this call would actually change server state (false = no-op)",
  ),
  checkResult: CheckResultSchema.nullable().describe(
    "CHECKSCRIPT result for putScript; null for setActive/deleteScript " +
      "(no script body to validate for those two operations)",
  ),
  refused: z.string().nullable().describe(
    "Set when the operation would be refused outright (CHECKSCRIPT " +
      "failure, delete-the-active-script, activate-a-nonexistent-script), " +
      "with the human-readable reason. before/after still reflect the " +
      "live/proposed state for visibility even when refused.",
  ),
  dryRun: z.literal(true),
  retrievedAt: z.iso.datetime(),
});

/** The result of a write method executed with dryRun=false (the only mutate path). */
const AppliedSchema = z.object({
  op: z.enum(["putScript", "setActive", "deleteScript"]),
  name: z.string(),
  action: z.enum(["put", "activate", "deactivate", "delete"]),
  before: z.string().nullable(),
  after: z.string().nullable(),
  changed: z.boolean(),
  checkResult: CheckResultSchema.nullable(),
  serverResponse: ServerResponseSchema.nullable().describe(
    "The server's final OK response to the mutate command; null when " +
      "changed=false (no command was ever sent)",
  ),
  error: z.string().optional().describe(
    "Set only on the partial-failure evidence written when the mutate " +
      "command threw after being transmitted (state may be unverified).",
  ),
  retrievedAt: z.iso.datetime(),
});

// ---------------------------------------------------------------------------
// Encoding helpers (exported for tests; no external deps)
// ---------------------------------------------------------------------------

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

/** Bytes -> standard base64, chunked to avoid a spread-operator stack blowup. */
export function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

/**
 * Build the base64 SASL PLAIN initial response: `authzid NUL authcid NUL
 * passwd` (RFC 4616), with an empty authzid.
 *
 * @param user The mailbox login (authcid).
 * @param password The mailbox password/app-password.
 * @returns The base64-encoded initial response, ready to be literal-encoded
 *   as the AUTHENTICATE command's second argument.
 */
export function buildSaslPlainInitialResponse(
  user: string,
  password: string,
): string {
  const authcid = textEncoder.encode(user);
  const passwd = textEncoder.encode(password);
  const bytes = new Uint8Array(1 + authcid.length + 1 + passwd.length);
  let o = 0;
  bytes[o++] = 0;
  bytes.set(authcid, o);
  o += authcid.length;
  bytes[o++] = 0;
  bytes.set(passwd, o);
  return bytesToBase64(bytes);
}

/**
 * Frame one value as an RFC 5804 non-synchronizing client literal:
 * `{n+}\r\n` followed by exactly `n` raw UTF-8 bytes. This is the ONLY
 * string-encoding this client ever sends -- never a quoted string -- so the
 * byte count fully determines where the value ends; no character sequence
 * inside `value` (CRLF, quotes, braces, a second fake command) can ever be
 * misread as a protocol boundary.
 *
 * @param value The raw string to frame (a script name or script text).
 * @returns The literal's complete wire bytes (header + payload, no
 *   trailing CRLF -- the caller's command-level CRLF terminates the line).
 */
export function encodeLiteral(value: string): Uint8Array {
  const payload = textEncoder.encode(value);
  const header = textEncoder.encode(`{${payload.length}+}\r\n`);
  const out = new Uint8Array(header.length + payload.length);
  out.set(header, 0);
  out.set(payload, header.length);
  return out;
}

/**
 * Assemble one complete ManageSieve command line: a trusted ASCII keyword
 * (never caller-controlled) followed by zero or more literal-encoded
 * arguments (always caller-controlled strings), terminated by CRLF.
 *
 * @param keyword The command keyword, e.g. "LISTSCRIPTS" (a fixed constant
 *   in this module, never derived from an argument).
 * @param args Grammar-`string` arguments, each framed via {@link
 *   encodeLiteral}.
 * @returns The complete command bytes ready to write to the transport.
 */
export function buildCommandBytes(
  keyword: string,
  args: string[] = [],
): Uint8Array {
  const parts: Uint8Array[] = [textEncoder.encode(keyword)];
  for (const a of args) {
    parts.push(textEncoder.encode(" "));
    parts.push(encodeLiteral(a));
  }
  parts.push(textEncoder.encode("\r\n"));
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/**
 * Sanitize a server-supplied free-text string before it is embedded into a
 * thrown Error message or a persisted resource (MS-5). ALL control bytes --
 * C0 (incl. CR, LF, TAB, ESC), DEL, and C1 -- are replaced with a single
 * space, whitespace runs are collapsed, and the result is capped. This
 * defeats log-line injection (fake newlines splicing forged log entries)
 * and terminal-escape injection from a malicious or compromised server,
 * whose NO/BYE text would otherwise flow verbatim into swamp logs and
 * report artifacts. No secrets are ever in this text; this is defense in
 * depth for untrusted output.
 *
 * @param s The raw server-supplied text.
 * @param maxLen Maximum retained length before truncation (default 200).
 * @returns A single-line, control-free, length-capped string.
 */
export function sanitizeServerText(s: string, maxLen = 200): string {
  // deno-lint-ignore no-control-regex -- intentional: collapsing control bytes (incl. CR/LF/ESC) is the entire point of this sanitizer.
  const stripped = s.replace(/[\u0000-\u001F\u007F-\u009F]/g, " ")
    .replace(/ +/g, " ")
    .trim();
  return stripped.length > maxLen
    ? stripped.slice(0, maxLen) + "..."
    : stripped;
}

/**
 * Split a multi-line literal (error/warning text) into trimmed, non-empty,
 * sanitized lines. The split preserves the server's own per-message line
 * structure; {@link sanitizeServerText} then strips any residual control
 * bytes and caps each line (MS-5).
 */
export function splitLines(s: string): string[] {
  return s.split(/\r\n|\r|\n/)
    .map((x) => sanitizeServerText(x, 500))
    .filter((x) => x.length > 0);
}

/** Strip one pair of surrounding double quotes and unescape `\X` -> `X`, if quoted. */
export function dequoteIfQuoted(s: string): string {
  if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) {
    return s.slice(1, -1).replace(/\\(.)/g, "$1");
  }
  return s;
}

/** One ManageSieve terminal response (`OK`/`NO`/`BYE`), parsed. */
export interface TerminalResponse {
  tag: "OK" | "NO" | "BYE";
  code: string | null;
  text: string | null;
}

const TERMINAL_RE = /^(OK|NO|BYE)(?:\s*\(([^)]*)\))?(?:\s+(.*))?$/is;

/**
 * Parse one already literal-resolved logical line as a ManageSieve terminal
 * response (`response-ok` / `response-nobye`), or return null if the line
 * does not have that shape (i.e. it is a data line, such as one
 * LISTSCRIPTS entry).
 *
 * @param line A logical line, as returned by {@link readLogicalLine}.
 * @returns The parsed terminal response, or null if `line` is a data line.
 */
export function tryParseTerminal(line: string): TerminalResponse | null {
  const m = TERMINAL_RE.exec(line);
  if (!m) return null;
  const tag = m[1].toUpperCase() as "OK" | "NO" | "BYE";
  const code = m[2] ?? null;
  const rawText = m[3];
  const text = rawText === undefined
    ? null
    : (dequoteIfQuoted(rawText) || null);
  return { tag, code, text };
}

/**
 * Render a {@link TerminalResponse} as a short, log-safe description for use
 * in a thrown Error. The server-supplied `code` and `text` are passed
 * through {@link sanitizeServerText} so a malicious server cannot inject
 * newlines or terminal escapes into our logs (MS-5).
 */
export function describeTerm(t: TerminalResponse): string {
  const code = t.code ? ` (${sanitizeServerText(t.code, 80)})` : "";
  const text = t.text ? ` ${sanitizeServerText(t.text)}` : "";
  return `${t.tag}${code}${text}`;
}

/**
 * Build a persisted {@link ServerResponseSchema} record from a terminal
 * response, sanitizing the server-supplied code/text first so untrusted
 * control bytes never land in a swamp data resource / report artifact
 * (MS-5).
 *
 * @param t The server's terminal response.
 * @returns A sanitized `{ tag, code, text }` record.
 */
export function toServerResponse(
  t: TerminalResponse,
): { tag: string; code: string | null; text: string | null } {
  return {
    tag: t.tag,
    code: t.code === null ? null : sanitizeServerText(t.code, 80),
    text: t.text === null ? null : sanitizeServerText(t.text),
  };
}

/**
 * Race a promise against a deadline (MS-1). If `ms` elapses first, `label`
 * is used to build a timeout Error, the optional `onTimeout` hook runs
 * (e.g. to close the socket), and the returned promise rejects. The
 * original promise still has a rejection handler attached, so a late
 * settlement after the timeout never surfaces as an unhandled rejection.
 * `ms <= 0` disables the deadline and returns `p` unchanged.
 *
 * @param p The operation to bound.
 * @param ms The deadline in milliseconds (0 disables).
 * @param label A short name for the operation (for the error message).
 * @param onTimeout Optional cleanup to run on timeout.
 * @returns A promise that settles with `p`, or rejects on timeout.
 */
export function withTimeout<T>(
  p: Promise<T>,
  ms: number,
  label: string,
  onTimeout?: () => void,
): Promise<T> {
  if (ms <= 0) return p;
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      if (onTimeout) {
        try {
          onTimeout();
        } catch {
          // best-effort cleanup; the timeout error is what matters
        }
      }
      reject(
        new Error(`ManageSieve ${label} timed out after ${ms} ms`),
      );
    }, ms);
    p.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      },
    );
  });
}

/**
 * Parse one LISTSCRIPTS data line: `sieve-name [SP "ACTIVE"] CRLF`, already
 * literal-resolved by {@link readLogicalLine}.
 *
 * @param line A logical data line from a LISTSCRIPTS response.
 * @returns The script's name and whether it carries the ACTIVE marker.
 */
export function parseScriptLine(line: string): ScriptEntry {
  const trimmed = line.trim();
  const activeMatch = /^(.*)\sACTIVE\s*$/i.exec(trimmed);
  const namePart = activeMatch ? activeMatch[1] : trimmed;
  return {
    name: dequoteIfQuoted(namePart.trim()),
    active: Boolean(activeMatch),
  };
}

const QUOTED_PAIR_RE = /^"((?:[^"\\]|\\.)*)"(?:\s+"((?:[^"\\]|\\.)*)")?\s*$/;

/**
 * Parse one capability line (`capability-name [SP string] CRLF`), already
 * literal-resolved by {@link readLogicalLine}. Handles the common
 * quoted-quoted and quoted-only shapes exactly; falls back to a
 * first-whitespace split for the (per the RFC's own examples, essentially
 * never used in practice) case where a server sends a capability name or
 * value as a literal rather than quoted.
 *
 * @param line A logical capability line from the greeting/capability block.
 * @returns The capability's name and optional value.
 */
export function parseCapabilityLine(
  line: string,
): { name: string; value: string | null } {
  const trimmed = line.trim();
  const m = QUOTED_PAIR_RE.exec(trimmed);
  if (m) {
    return {
      name: m[1].replace(/\\(.)/g, "$1"),
      value: m[2] !== undefined ? m[2].replace(/\\(.)/g, "$1") : null,
    };
  }
  const idx = trimmed.search(/\s/);
  if (idx === -1) return { name: dequoteIfQuoted(trimmed), value: null };
  const value = dequoteIfQuoted(trimmed.slice(idx + 1).trim());
  return { name: dequoteIfQuoted(trimmed.slice(0, idx)), value: value || null };
}

/**
 * Characters prohibited anywhere in a Sieve script name (RFC 5804 section
 * 1.6): C0/C1 control characters, DELETE, and the Unicode LINE/PARAGRAPH
 * SEPARATOR code points.
 */
// deno-lint-ignore no-control-regex -- intentional: rejecting these control/separator code points per RFC 5804 section 1.6 is the point of this check.
const FORBIDDEN_NAME_CHARS = /[\u0000-\u001F\u007F\u0080-\u009F\u2028\u2029]/;

/**
 * Validate a script name against the RFC 5804 section 1.6 grammar before it
 * ever reaches the wire. This is defense in depth on top of the literal
 * encoding (which already makes any content byte-safe to transmit) --
 * it rejects nonsensical names early with a clear message rather than
 * letting the server reject them later.
 *
 * @param name The raw script name supplied by a caller.
 * @param opts `allowEmpty`: true for `setActive`'s deactivate sentinel.
 * @throws If the name is empty (and not allowed to be), too long, or
 *   contains a forbidden character.
 */
export function validateScriptName(
  name: string,
  opts: { allowEmpty?: boolean } = {},
): void {
  if (name.length === 0) {
    if (opts.allowEmpty) return;
    throw new Error("Script name must not be empty");
  }
  if (name.length > 128) {
    throw new Error(
      `Script name too long (${name.length} chars): RFC 5804 servers are ` +
        "only required to support up to 128 Unicode characters.",
    );
  }
  if (FORBIDDEN_NAME_CHARS.test(name)) {
    throw new Error(
      `Invalid script name "${name}": contains a control character or ` +
        "line/paragraph separator forbidden by RFC 5804 section 1.6.",
    );
  }
}

/**
 * Encode a script name into a collision-free resource-instance slug, using
 * the same scheme as `@shrug/imap`'s `folderSlug`: every character outside
 * `[A-Za-z0-9_.-]` is percent-escaped as `%` plus its fixed-width 4-hex
 * UTF-16 code unit, so distinct names always produce distinct slugs.
 *
 * @param name The script name.
 * @returns A filesystem-safe, collision-free slug.
 */
export function scriptSlug(name: string): string {
  return name
    .split("")
    .map((ch) =>
      /[A-Za-z0-9_.-]/.test(ch)
        ? ch
        : "%" + ch.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")
    )
    .join("");
}

/**
 * SHA-256 hex digest of a script's text, used as a collision-free resource
 * instance key for `checkScript` (which has no script name to key on).
 *
 * @param text The Sieve script source.
 * @returns The lowercase hex SHA-256 digest.
 */
export async function digestHex(text: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", textEncoder.encode(text));
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---------------------------------------------------------------------------
// Transport seam (the sole network boundary; injected in tests)
// ---------------------------------------------------------------------------

/**
 * The raw byte-level transport this client depends on. This is the ONE
 * injectable seam: every protocol-level function below (handshake,
 * AUTHENTICATE, every command) operates purely against this interface, so
 * tests exercise the real command-encoding and response-parsing logic
 * against a synthetic scripted transport, never a live socket.
 */
export interface SieveTransport {
  /** Open the underlying connection. */
  connect(): Promise<void>;
  /** Read one CRLF (or bare LF)-terminated line, decoded as UTF-8, terminator stripped. */
  readLine(): Promise<string>;
  /** Read exactly `n` raw bytes (used for literal-s2c content; never line-split). */
  readExact(n: number): Promise<Uint8Array>;
  /** Write raw bytes to the wire. */
  write(data: Uint8Array): Promise<void>;
  /**
   * Upgrade the connection to TLS in place (STARTTLS). Implementations MUST
   * discard any bytes already buffered from the plaintext connection before
   * the upgrade completes -- see the module doc's "STARTTLS
   * plaintext-injection guard" section. Only bytes read from the new
   * TLS-wrapped connection may ever be trusted afterward.
   */
  startTls(hostname: string): Promise<void>;
  /** Close the connection (best-effort; never throws). */
  close(): Promise<void>;
}

/** Builds a connected-on-demand transport for the given config. */
export type ClientFactory = (cfg: GlobalArgs) => SieveTransport;

/**
 * The minimal read surface {@link LineReader} depends on -- structurally
 * satisfied by `Deno.TcpConn`/`Deno.TlsConn`, and trivially stubbable in
 * tests without building a full fake `Deno.Conn`.
 */
export interface ByteReader {
  read(p: Uint8Array): Promise<number | null>;
}

/**
 * Buffers raw bytes from a {@link ByteReader} and exposes line- and
 * exact-byte-count reads. `setConn` (used on STARTTLS upgrade) always
 * discards the current buffer -- see {@link SieveTransport.startTls}. This
 * class, and its discard-on-swap behavior, is directly unit tested.
 *
 * Each underlying socket read is bounded by `timeoutMs` (MS-1): a server
 * that stalls mid-response rejects rather than hangs forever. `readLine`
 * additionally caps total buffered bytes at {@link MAX_LINE_BYTES} (MS-2):
 * a server streaming without a terminator is aborted instead of growing
 * memory without limit.
 */
export class LineReader {
  #buf: Uint8Array = new Uint8Array(0);
  #conn: ByteReader;
  #timeoutMs: number;

  constructor(conn: ByteReader, timeoutMs = 0) {
    this.#conn = conn;
    this.#timeoutMs = timeoutMs;
  }

  /** Swap the underlying connection, discarding any buffered bytes from the old one. */
  setConn(conn: ByteReader): void {
    this.#conn = conn;
    this.#buf = new Uint8Array(0);
  }

  async #fill(): Promise<boolean> {
    const chunk = new Uint8Array(4096);
    const n = await withTimeout(
      this.#conn.read(chunk),
      this.#timeoutMs,
      "socket read",
    );
    if (n === null) return false;
    const merged = new Uint8Array(this.#buf.length + n);
    merged.set(this.#buf, 0);
    merged.set(chunk.subarray(0, n), this.#buf.length);
    this.#buf = merged;
    return true;
  }

  async readLine(): Promise<string> {
    for (;;) {
      const idx = this.#buf.indexOf(0x0a);
      if (idx !== -1) {
        let end = idx;
        if (end > 0 && this.#buf[end - 1] === 0x0d) end--;
        const text = textDecoder.decode(this.#buf.subarray(0, end));
        this.#buf = this.#buf.slice(idx + 1);
        return text;
      }
      if (this.#buf.length > MAX_LINE_BYTES) {
        throw new Error(
          `ManageSieve response line exceeded ${MAX_LINE_BYTES} bytes with ` +
            "no terminator; aborting (possible malicious or malfunctioning " +
            "server).",
        );
      }
      if (!(await this.#fill())) {
        throw new Error(
          "ManageSieve connection closed while waiting for a line",
        );
      }
    }
  }

  async readExact(n: number): Promise<Uint8Array> {
    while (this.#buf.length < n) {
      if (!(await this.#fill())) {
        throw new Error(
          `ManageSieve connection closed after ${this.#buf.length}/${n} ` +
            "literal bytes",
        );
      }
    }
    const out = this.#buf.slice(0, n);
    this.#buf = this.#buf.slice(n);
    return out;
  }
}

/**
 * The minimal duplex socket surface {@link defaultTransportFactory} needs --
 * structurally satisfied by `Deno.TcpConn`/`Deno.TlsConn`. Abstracting it
 * lets a test inject fake connections and drive the REAL STARTTLS-upgrade
 * wiring (MS-4) without opening a socket.
 */
export interface ByteConn extends ByteReader {
  write(p: Uint8Array): Promise<number>;
  close(): void;
}

/**
 * The socket primitives {@link defaultTransportFactory} depends on. The
 * production default ({@link realTransportDeps}) wraps `Deno.connect` /
 * `Deno.startTls`; tests inject fakes to exercise the upgrade ordering.
 */
export interface TransportDeps {
  connect(cfg: GlobalArgs): Promise<ByteConn>;
  startTls(
    conn: ByteConn,
    hostname: string,
    rejectUnauthorized: boolean,
  ): Promise<ByteConn>;
}

/** Production socket primitives: real TCP + real TLS upgrade via Deno. */
export const realTransportDeps: TransportDeps = {
  connect: (cfg) =>
    Deno.connect({ hostname: cfg.host, port: cfg.port }) as Promise<ByteConn>,
  // STARTTLS is only ever issued once, immediately after connect(), on the
  // plain TCP socket -- the cast reflects that protocol invariant.
  startTls: (conn, hostname, rejectUnauthorized) =>
    Deno.startTls(conn as Deno.TcpConn, {
      hostname,
      unsafelyDisableHostnameVerification: !rejectUnauthorized,
    }) as Promise<ByteConn>,
};

/**
 * Default transport factory: real TCP via `Deno.connect`, upgraded to TLS
 * via `Deno.startTls` on STARTTLS. No npm/jsr dependency and no host
 * binary -- this runs anywhere the Deno runtime does.
 *
 * Every socket operation (connect, TLS upgrade, each read, each write) is
 * bounded by `cfg.timeoutMs` (MS-1): on timeout the socket is closed and
 * the operation rejects, so a stalled server can never hang the method.
 *
 * The socket primitives are injected via `deps` (defaulting to
 * {@link realTransportDeps}) so a test can drive the real
 * STARTTLS-discard wiring -- `conn = tlsConn; reader.setConn(tlsConn)` --
 * with fake connections, without opening a socket (MS-4).
 *
 * @param cfg Resolved connection + credential settings.
 * @param deps Socket primitives (default: real Deno TCP/TLS).
 * @returns A {@link SieveTransport} backed by real sockets.
 */
export function defaultTransportFactory(
  cfg: GlobalArgs,
  deps: TransportDeps = realTransportDeps,
): SieveTransport {
  let conn: ByteConn | null = null;
  let reader: LineReader | null = null;
  const closeConn = () => {
    try {
      conn?.close();
    } catch {
      // already closed
    }
  };
  return {
    async connect() {
      // If the deadline fires before deps.connect settles, withTimeout rejects
      // and `conn` is never assigned -- so a socket that resolves late would be
      // dropped un-closed (an fd leak). Hold the connect promise and, on
      // timeout, close whatever it eventually yields. (write/startTls close an
      // already-captured `conn`; connect has none yet, so it must close the
      // late arrival itself.)
      const connecting = deps.connect(cfg);
      conn = await withTimeout(connecting, cfg.timeoutMs, "connect", () => {
        connecting
          .then((late) => {
            try {
              late.close();
            } catch {
              // already closed / never fully opened
            }
          })
          .catch(() => {
            // connect ultimately failed; nothing to close
          });
      });
      reader = new LineReader(conn, cfg.timeoutMs);
    },
    readLine() {
      // Return a rejected Promise rather than throwing synchronously, so
      // every SieveTransport method is Promise-consistent even for a
      // caller that doesn't `await` before attaching a `.catch`.
      if (!reader) {
        return Promise.reject(
          new Error("ManageSieve transport not connected"),
        );
      }
      return reader.readLine();
    },
    readExact(n: number) {
      if (!reader) {
        return Promise.reject(
          new Error("ManageSieve transport not connected"),
        );
      }
      return reader.readExact(n);
    },
    async write(data: Uint8Array) {
      if (!conn) throw new Error("ManageSieve transport not connected");
      let written = 0;
      while (written < data.length) {
        written += await withTimeout(
          conn.write(data.subarray(written)),
          cfg.timeoutMs,
          "socket write",
          closeConn,
        );
      }
    },
    async startTls(hostname: string) {
      if (!conn || !reader) {
        throw new Error("ManageSieve transport not connected");
      }
      // The TLS handshake runs directly against the raw socket; it does not
      // consult our application-level buffer. The important safety step is
      // reader.setConn() below, which discards whatever (untrusted,
      // plaintext-era) bytes are sitting in our buffer so they can never be
      // replayed as post-upgrade data (the headline injection guard).
      const tlsConn = await withTimeout(
        deps.startTls(conn, hostname, cfg.tlsRejectUnauthorized),
        cfg.timeoutMs,
        "STARTTLS upgrade",
        closeConn,
      );
      conn = tlsConn;
      reader.setConn(tlsConn);
    },
    close() {
      closeConn();
      return Promise.resolve();
    },
  };
}

// ---------------------------------------------------------------------------
// Protocol layer (pure-ish functions over a SieveTransport; exported for tests)
// ---------------------------------------------------------------------------

/**
 * One logical response line, classified by FRAMING (MS-3).
 *
 * `isTerminal` is decided from the HEAD line alone, before any literal is
 * resolved: a terminal response (`response-ok`/`response-nobye`) begins
 * with a bare `OK`/`NO`/`BYE` atom, whereas every DATA line (a LISTSCRIPTS
 * sieve-name, a GETSCRIPT script body) is a `string` -- quoted, or a pure
 * `{n}` literal -- and so never begins with that atom. The terminal
 * OK/NO/BYE grammar is therefore matched ONLY on lines framed as terminal,
 * never on literal payload bytes. This is what makes a GETSCRIPT body whose
 * text happens to start with `ok`/`no`/`bye` safe: it arrives as a literal
 * data line, is flagged `isTerminal: false`, and is returned verbatim
 * instead of being misparsed as a response (which previously broke
 * `cmdGetScript`, and in turn `putScript`'s own before/after diff).
 */
export interface LogicalLine {
  /** True iff the head was framed as a terminal OK/NO/BYE response line. */
  isTerminal: boolean;
  /** The fully resolved line text (any server literal spliced in). */
  text: string;
}

/**
 * Read one logical response line, resolving an embedded server literal
 * (literal-s2c, `{n}` with no `+`) inline. A literal's raw bytes are read
 * via {@link SieveTransport.readExact}, never split on embedded CRLF, so a
 * multi-line script/error body transmitted as one literal comes back
 * intact; any trailing tokens on the same logical line after the literal
 * (e.g. ` ACTIVE`) are then read as the rest of the line.
 *
 * The server-declared literal octet count is validated against
 * {@link MAX_LITERAL_BYTES} BEFORE any allocation (MS-2): an over-cap or
 * non-finite count is rejected rather than trusted.
 *
 * @param t The transport to read from.
 * @returns The classified, fully resolved logical line.
 */
export async function readLogicalLine(t: SieveTransport): Promise<LogicalLine> {
  const head = await t.readLine();
  // Framing decision happens on the raw head, before resolving any literal:
  // only a line that BEGINS with a bare OK/NO/BYE atom is a terminal
  // response. (A terminal response MAY still carry its human text as a
  // trailing literal, e.g. `NO (NONEXISTENT) {31}`, which is resolved below
  // and still parses as terminal.)
  const isTerminal = TERMINAL_RE.test(head);
  const m = /\{(\d+)\}$/.exec(head);
  if (!m) return { isTerminal, text: head };
  const n = Number(m[1]);
  if (!Number.isSafeInteger(n) || n < 0 || n > MAX_LITERAL_BYTES) {
    throw new Error(
      `Refusing a server literal of ${m[1]} octets: exceeds the ` +
        `${MAX_LITERAL_BYTES}-byte cap (possible malicious or malfunctioning ` +
        "server).",
    );
  }
  const prefix = head.slice(0, head.length - m[0].length);
  const bytes = await t.readExact(n);
  const literalText = textDecoder.decode(bytes);
  const suffix = await t.readLine();
  return { isTerminal, text: prefix + literalText + suffix };
}

/**
 * Read one logical line and require it to be framed as a terminal
 * OK/NO/BYE response, returning the parsed {@link TerminalResponse}. Throws
 * if the line is a data line (wrong framing) or cannot be parsed. Used by
 * every command whose next expected line is a terminal response.
 *
 * @param t The transport to read from.
 * @param cmd A short command label for error messages.
 * @returns The parsed terminal response (tag may be OK, NO, or BYE).
 * @throws If the line is not a terminal response.
 */
export async function readTerminal(
  t: SieveTransport,
  cmd: string,
): Promise<TerminalResponse> {
  const line = await readLogicalLine(t);
  if (!line.isTerminal) {
    throw new Error(
      `${cmd}: expected a terminal OK/NO/BYE response but the server sent a ` +
        "data line",
    );
  }
  const term = tryParseTerminal(line.text);
  if (!term) throw new Error(`${cmd}: unparseable server response`);
  return term;
}

/**
 * Read a capability block (`*(single-capability) response-oknobye`) -- used
 * both for the initial greeting and for the re-issued post-STARTTLS block.
 *
 * @param t The transport to read from.
 * @returns A map of uppercased capability name to its value (empty string
 *   if the capability has no value, e.g. STARTTLS).
 * @throws If the terminal response is NO/BYE instead of OK.
 */
export async function readCapabilities(
  t: SieveTransport,
): Promise<Map<string, string>> {
  const caps = new Map<string, string>();
  for (;;) {
    const line = await readLogicalLine(t);
    if (line.isTerminal) {
      const term = tryParseTerminal(line.text);
      if (!term || term.tag !== "OK") {
        throw new Error(
          `ManageSieve greeting/capability negotiation failed: ${
            term ? describeTerm(term) : "unparseable response"
          }`,
        );
      }
      return caps;
    }
    const cap = parseCapabilityLine(line.text);
    caps.set(cap.name.toUpperCase(), cap.value ?? "");
  }
}

/**
 * Perform the full connect sequence: open the transport, read the greeting,
 * STARTTLS (refusing to proceed without it unless `allowInsecure`), and
 * AUTHENTICATE PLAIN. On return the transport is ready for script-management
 * commands.
 *
 * @param transport The transport to connect and authenticate.
 * @param cfg Resolved connection + credential settings.
 * @throws If STARTTLS is unavailable (and not allowed insecure), if the
 *   server does not advertise SASL PLAIN, or if authentication fails.
 */
export async function sieveConnect(
  transport: SieveTransport,
  cfg: GlobalArgs,
): Promise<void> {
  await transport.connect();
  let caps = await readCapabilities(transport);

  if (caps.has("STARTTLS")) {
    await transport.write(buildCommandBytes("STARTTLS"));
    const term = await readTerminal(transport, "STARTTLS");
    if (term.tag !== "OK") {
      throw new Error(`STARTTLS failed: ${describeTerm(term)}`);
    }
    await transport.startTls(cfg.host);
    caps = await readCapabilities(transport);
  } else if (!cfg.allowInsecure) {
    throw new Error(
      `Refusing to authenticate: ${cfg.host}:${cfg.port} does not advertise ` +
        "STARTTLS and allowInsecure is not set. Set allowInsecure=true only " +
        "for a known test/dev server.",
    );
  }

  const saslMechs = (caps.get("SASL") ?? "").toUpperCase().split(/\s+/)
    .filter(Boolean);
  if (!saslMechs.includes("PLAIN")) {
    throw new Error(
      "Refusing to authenticate: server does not advertise SASL PLAIN " +
        `(SASL="${caps.get("SASL") ?? ""}").`,
    );
  }

  const initialResponse = buildSaslPlainInitialResponse(cfg.user, cfg.password);
  await transport.write(
    buildCommandBytes("AUTHENTICATE", ["PLAIN", initialResponse]),
  );
  const authTerm = await readTerminal(transport, "AUTHENTICATE PLAIN");
  if (authTerm.tag !== "OK") {
    throw new Error(
      `AUTHENTICATE PLAIN failed for user ${cfg.user}: ${
        describeTerm(authTerm)
      }`,
    );
  }
}

/**
 * LISTSCRIPTS: enumerate the user's scripts.
 *
 * @param t An authenticated transport.
 * @returns Every script with its active flag.
 * @throws If the server returns NO/BYE.
 */
export async function cmdListScripts(
  t: SieveTransport,
): Promise<ScriptEntry[]> {
  await t.write(buildCommandBytes("LISTSCRIPTS"));
  const scripts: ScriptEntry[] = [];
  for (;;) {
    const line = await readLogicalLine(t);
    if (line.isTerminal) {
      const term = tryParseTerminal(line.text);
      if (!term || term.tag !== "OK") {
        throw new Error(
          `LISTSCRIPTS failed: ${
            term ? describeTerm(term) : "unparseable response"
          }`,
        );
      }
      return scripts;
    }
    scripts.push(parseScriptLine(line.text));
  }
}

/**
 * GETSCRIPT: fetch one script's raw text.
 *
 * @param t An authenticated transport.
 * @param name The script name.
 * @returns The script's raw text.
 * @throws If the script does not exist (NO, typically NONEXISTENT) or the
 *   server returns BYE.
 */
export async function cmdGetScript(
  t: SieveTransport,
  name: string,
): Promise<string> {
  await t.write(buildCommandBytes("GETSCRIPT", [name]));
  const first = await readLogicalLine(t);
  if (first.isTerminal) {
    // A terminal line in the FIRST position means GETSCRIPT failed (a
    // success always sends the script content first). Because the decision
    // is framing-based, a script body that merely starts with ok/no/bye --
    // which arrives as a non-terminal literal data line -- is correctly
    // treated as content, not a response (MS-3).
    const term = tryParseTerminal(first.text);
    throw new Error(
      `GETSCRIPT "${name}" failed: ${
        term ? describeTerm(term) : "unparseable response"
      }`,
    );
  }
  const content = first.text;
  const term = await readTerminal(t, `GETSCRIPT "${name}"`);
  if (term.tag !== "OK") {
    throw new Error(
      `GETSCRIPT "${name}": unexpected trailing response after content: ${
        describeTerm(term)
      }`,
    );
  }
  return content;
}

/** The outcome of a CHECKSCRIPT (or pre-PUTSCRIPT) validation call. */
export interface CheckOutcome {
  ok: boolean;
  errors: string[];
  warnings: string[];
  code: string | null;
}

/**
 * CHECKSCRIPT: validate a script's syntax without installing it.
 *
 * @param t An authenticated transport.
 * @param text The Sieve script source to validate.
 * @returns Whether the script is valid, plus any error/warning lines.
 * @throws If the server returns BYE (connection closing).
 */
export async function cmdCheckScript(
  t: SieveTransport,
  text: string,
): Promise<CheckOutcome> {
  await t.write(buildCommandBytes("CHECKSCRIPT", [text]));
  const term = await readTerminal(t, "CHECKSCRIPT");
  if (term.tag === "BYE") {
    throw new Error(
      `ManageSieve server closed the connection (BYE): ${
        term.text ? sanitizeServerText(term.text) : "no reason given"
      }`,
    );
  }
  if (term.tag === "OK") {
    const warnings = term.code === "WARNINGS" && term.text
      ? splitLines(term.text)
      : [];
    return { ok: true, errors: [], warnings, code: term.code };
  }
  const errors = term.text
    ? splitLines(term.text)
    : ["CHECKSCRIPT rejected the script (no message given)"];
  return { ok: false, errors, warnings: [], code: term.code };
}

/**
 * PUTSCRIPT: submit a script, overwriting any existing script of the same
 * name. Callers are expected to have already run {@link cmdCheckScript} --
 * this function does not check, it only submits.
 *
 * @param t An authenticated transport.
 * @param name The script name.
 * @param text The Sieve script source.
 * @returns The server's OK response.
 * @throws If the server returns NO/BYE.
 */
export async function cmdPutScript(
  t: SieveTransport,
  name: string,
  text: string,
): Promise<TerminalResponse> {
  await t.write(buildCommandBytes("PUTSCRIPT", [name, text]));
  const term = await readTerminal(t, `PUTSCRIPT "${name}"`);
  if (term.tag !== "OK") {
    throw new Error(`PUTSCRIPT "${name}" failed: ${describeTerm(term)}`);
  }
  return term;
}

/**
 * SETACTIVE: mark a script active, or (name="") deactivate.
 *
 * @param t An authenticated transport.
 * @param name The script name, or "" to deactivate.
 * @returns The server's OK response.
 * @throws If the server returns NO/BYE.
 */
export async function cmdSetActive(
  t: SieveTransport,
  name: string,
): Promise<TerminalResponse> {
  await t.write(buildCommandBytes("SETACTIVE", [name]));
  const term = await readTerminal(t, `SETACTIVE "${name}"`);
  if (term.tag !== "OK") {
    throw new Error(`SETACTIVE "${name}" failed: ${describeTerm(term)}`);
  }
  return term;
}

/**
 * DELETESCRIPT: delete a script. The server itself refuses to delete the
 * active script (NO with the ACTIVE response code); this function does not
 * pre-check, it only submits -- the model's `deleteScript` method performs
 * the client-side active-script guard before ever calling this.
 *
 * @param t An authenticated transport.
 * @param name The script name.
 * @returns The server's OK response.
 * @throws If the server returns NO/BYE.
 */
export async function cmdDeleteScript(
  t: SieveTransport,
  name: string,
): Promise<TerminalResponse> {
  await t.write(buildCommandBytes("DELETESCRIPT", [name]));
  const term = await readTerminal(t, `DELETESCRIPT "${name}"`);
  if (term.tag !== "OK") {
    throw new Error(`DELETESCRIPT "${name}" failed: ${describeTerm(term)}`);
  }
  return term;
}

/**
 * LOGOUT: best-effort graceful close. Never throws -- callers run this in a
 * cleanup path alongside {@link SieveTransport.close}.
 *
 * @param t The transport to log out of.
 */
export async function cmdLogout(t: SieveTransport): Promise<void> {
  await t.write(buildCommandBytes("LOGOUT"));
  try {
    await readLogicalLine(t);
  } catch {
    // The server MAY close the connection immediately after LOGOUT; either
    // way this is best-effort and the caller closes the transport next.
  }
}

// ---------------------------------------------------------------------------
// Context + method helpers
// ---------------------------------------------------------------------------

/** Minimal logging surface the methods rely on. */
interface MethodLogger {
  info(message: string, properties?: Record<string, unknown>): void;
  warning(message: string, properties?: Record<string, unknown>): void;
}

/** Minimal shape of the execute context this model relies on. */
interface ExecuteContext {
  globalArgs: GlobalArgs;
  logger: MethodLogger;
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
}

/** Return shape for every method's execute function. */
interface ExecuteResult {
  dataHandles: Array<{ name: string }>;
}

/** Always run after a method's command sequence, success or failure. */
async function cleanup(transport: SieveTransport): Promise<void> {
  await cmdLogout(transport).catch(() => {});
  await transport.close();
}

// ---------------------------------------------------------------------------
// Model definition
// ---------------------------------------------------------------------------

/** Provider-agnostic ManageSieve (RFC 5804) read-only + gated write model. */
export const model = {
  type: "@shrug/managesieve",
  version: "2026.10.03.1",
  description:
    "Provider-agnostic ManageSieve (RFC 5804) over native Deno TCP/TLS " +
    "(no npm dependency): read-only listScripts/getScript/getActive/" +
    "checkScript, plus gated write methods putScript/setActive/" +
    "deleteScript. dryRun defaults true and is the only non-mutating path; " +
    "putScript always CHECKSCRIPTs first and refuses to mutate on failure; " +
    "deleteScript refuses to remove the currently active script; every " +
    "write is idempotent (unchanged state is a recorded no-op, zero " +
    "commands sent). Script names/text are always sent as non-synchronizing " +
    "RFC 5804 literals, which are purely length-prefixed and therefore " +
    "immune to command injection regardless of content.",
  globalArguments: GlobalArgsSchema,
  resources: {
    "scripts": {
      description: "The full set of Sieve scripts on the server (LISTSCRIPTS)",
      schema: ScriptListSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "script": {
      description: "The raw text of one Sieve script (GETSCRIPT)",
      schema: ScriptContentSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "activeScript": {
      description: "The currently active Sieve script name, or null",
      schema: ActiveScriptSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "checkResult": {
      description: "A CHECKSCRIPT validation result for ad-hoc script text",
      schema: CheckResultSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "wouldAffect": {
      description:
        "A dryRun=true preview of a write method's effect; NO mutation performed",
      schema: WouldAffectSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "applied": {
      description: "The result of a write method executed with dryRun=false",
      schema: AppliedSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
  },
  methods: {
    listScripts: {
      description:
        "Enumerate the user's Sieve scripts (LISTSCRIPTS) and flag which " +
        "one is active. Read-only.",
      arguments: z.object({}),
      execute: async (
        args: { _transport?: ClientFactory },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const transport = (args._transport ?? defaultTransportFactory)(cfg);
        try {
          await sieveConnect(transport, cfg);
          const scripts = await cmdListScripts(transport);
          context.logger.info("Listed {n} sieve script(s) on {host}", {
            n: scripts.length,
            host: cfg.host,
          });
          const handle = await context.writeResource("scripts", "list", {
            scripts,
            count: scripts.length,
            retrievedAt: new Date().toISOString(),
          });
          return { dataHandles: [handle] };
        } finally {
          await cleanup(transport);
        }
      },
    },
    getScript: {
      description:
        "Fetch the raw text of one Sieve script (GETSCRIPT). Read-only.",
      arguments: z.object({
        name: z.string().min(1).describe(
          "Script name, as returned by listScripts",
        ),
      }),
      execute: async (
        args: { name: string; _transport?: ClientFactory },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        validateScriptName(args.name);
        const cfg = context.globalArgs;
        const transport = (args._transport ?? defaultTransportFactory)(cfg);
        try {
          await sieveConnect(transport, cfg);
          context.logger.info("Fetching sieve script {name} from {host}", {
            name: args.name,
            host: cfg.host,
          });
          const content = await cmdGetScript(transport, args.name);
          context.logger.info("Fetched sieve script {name} ({bytes} bytes)", {
            name: args.name,
            bytes: textEncoder.encode(content).length,
          });
          const handle = await context.writeResource(
            "script",
            `script:${scriptSlug(args.name)}`,
            {
              name: args.name,
              content,
              size: textEncoder.encode(content).length,
              retrievedAt: new Date().toISOString(),
            },
          );
          return { dataHandles: [handle] };
        } finally {
          await cleanup(transport);
        }
      },
    },
    getActive: {
      description:
        "Report the currently active Sieve script name, or null if none " +
        "is active. Derived from LISTSCRIPTS. Read-only.",
      arguments: z.object({}),
      execute: async (
        args: { _transport?: ClientFactory },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const transport = (args._transport ?? defaultTransportFactory)(cfg);
        try {
          await sieveConnect(transport, cfg);
          context.logger.info("Reading active sieve script on {host}", {
            host: cfg.host,
          });
          const scripts = await cmdListScripts(transport);
          const active = scripts.find((s) => s.active)?.name ?? null;
          context.logger.info("Active sieve script is {name}", {
            name: active ?? "(none)",
          });
          const handle = await context.writeResource("activeScript", "active", {
            name: active,
            retrievedAt: new Date().toISOString(),
          });
          return { dataHandles: [handle] };
        } finally {
          await cleanup(transport);
        }
      },
    },
    checkScript: {
      description:
        "Validate a Sieve script against the server's interpreter WITHOUT " +
        "installing it (CHECKSCRIPT). Read-only -- never calls PUTSCRIPT.",
      arguments: z.object({
        text: z.string().min(1).describe("Sieve script source to validate"),
      }),
      execute: async (
        args: { text: string; _transport?: ClientFactory },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const transport = (args._transport ?? defaultTransportFactory)(cfg);
        try {
          await sieveConnect(transport, cfg);
          context.logger.info(
            "Checking sieve script ({bytes} bytes) on {host}",
            { bytes: textEncoder.encode(args.text).length, host: cfg.host },
          );
          const result = await cmdCheckScript(transport, args.text);
          context.logger.info("Checked sieve script: ok={ok}", {
            ok: result.ok,
          });
          const digest = await digestHex(args.text);
          const handle = await context.writeResource(
            "checkResult",
            `check:${digest}`,
            {
              ok: result.ok,
              errors: result.errors,
              warnings: result.warnings,
              code: result.code,
              retrievedAt: new Date().toISOString(),
            },
          );
          return { dataHandles: [handle] };
        } finally {
          await cleanup(transport);
        }
      },
    },
    putScript: {
      description:
        "Submit a Sieve script (PUTSCRIPT), always CHECKSCRIPT-ing it " +
        "first regardless of dryRun -- refuses to mutate if validation " +
        "fails. dryRun defaults to true: computes a wouldAffect preview " +
        "(including the CHECKSCRIPT result) with ZERO server mutation. " +
        "dryRun=false is the only mutate path. Idempotent: a " +
        "byte-identical live script is a recorded no-op (no PUTSCRIPT is " +
        "ever sent for unchanged content).",
      arguments: z.object({
        name: z.string().min(1).describe("Script name to create/overwrite"),
        text: z.string().min(1).describe("Sieve script source"),
        dryRun: z.boolean().default(true).describe(
          "true (default): preview only, zero mutation. false: mutate.",
        ),
      }),
      execute: async (
        args: {
          name: string;
          text: string;
          dryRun?: boolean;
          _transport?: ClientFactory;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        validateScriptName(args.name);
        const dryRun = args.dryRun ?? true;
        const cfg = context.globalArgs;
        const transport = (args._transport ?? defaultTransportFactory)(cfg);
        const instanceName = `put:${scriptSlug(args.name)}`;
        try {
          await sieveConnect(transport, cfg);

          // PHASE 1 -- inspect (read-only: LISTSCRIPTS, GETSCRIPT if it
          // exists, CHECKSCRIPT -- always, regardless of dryRun).
          const scripts = await cmdListScripts(transport);
          const entry = scripts.find((s) => s.name === args.name);
          const before = entry
            ? await cmdGetScript(transport, args.name)
            : null;
          const changed = before !== args.text;
          const check = await cmdCheckScript(transport, args.text);
          const checkResource = {
            ok: check.ok,
            errors: check.errors,
            warnings: check.warnings,
            code: check.code,
            retrievedAt: new Date().toISOString(),
          };
          const refused = !check.ok
            ? `CHECKSCRIPT rejected the script: ${check.errors.join("; ")}`
            : null;

          if (dryRun) {
            context.logger.info(
              "Previewed putScript for {name} (dryRun, no mutation)",
              { name: args.name },
            );
            const handle = await context.writeResource(
              "wouldAffect",
              instanceName,
              {
                op: "putScript",
                name: args.name,
                action: "put",
                before,
                after: args.text,
                changed: changed && !refused,
                checkResult: checkResource,
                refused,
                dryRun: true,
                retrievedAt: new Date().toISOString(),
              },
            );
            return { dataHandles: [handle] };
          }

          if (refused) {
            throw new Error(`Refusing to PUTSCRIPT "${args.name}": ${refused}`);
          }

          if (!changed) {
            const handle = await context.writeResource(
              "applied",
              instanceName,
              {
                op: "putScript",
                name: args.name,
                action: "put",
                before,
                after: args.text,
                changed: false,
                checkResult: checkResource,
                serverResponse: null,
                retrievedAt: new Date().toISOString(),
              },
            );
            return { dataHandles: [handle] };
          }

          // PHASE 2 -- mutate.
          context.logger.info("Putting sieve script {name} ({bytes} bytes)", {
            name: args.name,
            bytes: textEncoder.encode(args.text).length,
          });
          let term: TerminalResponse;
          try {
            term = await cmdPutScript(transport, args.name, args.text);
          } catch (err) {
            await context.writeResource("applied", instanceName, {
              op: "putScript",
              name: args.name,
              action: "put",
              before,
              after: args.text,
              changed: false,
              checkResult: checkResource,
              serverResponse: null,
              error: err instanceof Error ? err.message : String(err),
              retrievedAt: new Date().toISOString(),
            });
            throw err;
          }
          const handle = await context.writeResource("applied", instanceName, {
            op: "putScript",
            name: args.name,
            action: "put",
            before,
            after: args.text,
            changed: true,
            checkResult: checkResource,
            serverResponse: toServerResponse(term),
            retrievedAt: new Date().toISOString(),
          });
          return { dataHandles: [handle] };
        } finally {
          await cleanup(transport);
        }
      },
    },
    setActive: {
      description:
        'Mark a script active (SETACTIVE); name="" deactivates. dryRun ' +
        "defaults to true. Idempotent: activating/deactivating the " +
        "already-active state is a recorded no-op. Refuses to activate a " +
        "name LISTSCRIPTS does not report.",
      arguments: z.object({
        name: z.string().describe(
          'Script name to activate, or "" to deactivate',
        ),
        dryRun: z.boolean().default(true).describe(
          "true (default): preview only, zero mutation. false: mutate.",
        ),
      }),
      execute: async (
        args: { name: string; dryRun?: boolean; _transport?: ClientFactory },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        if (args.name !== "") validateScriptName(args.name);
        const dryRun = args.dryRun ?? true;
        const cfg = context.globalArgs;
        const transport = (args._transport ?? defaultTransportFactory)(cfg);
        // The deactivate case (name "") has no script name; give it a
        // dedicated instance name rather than a sentinel slug. A slug can never
        // contain a raw ":" (scriptSlug percent-escapes everything outside
        // [A-Za-z0-9_.-]), so "deactivate" cannot collide with activate:<slug>
        // for ANY script name -- including one literally named "__none__",
        // which the old "activate:__none__" sentinel aliased.
        const instanceName = args.name === ""
          ? "deactivate"
          : `activate:${scriptSlug(args.name)}`;
        try {
          await sieveConnect(transport, cfg);
          const scripts = await cmdListScripts(transport);
          const currentActive = scripts.find((s) => s.active)?.name ?? null;
          const after = args.name === "" ? null : args.name;
          const action = after === null ? "deactivate" : "activate";
          const refused = after !== null && !scripts.some((s) =>
              s.name === after
            )
            ? `Script "${after}" does not exist (not reported by LISTSCRIPTS)`
            : null;
          const changed = !refused && currentActive !== after;

          if (dryRun) {
            context.logger.info(
              "Previewed setActive to {name} (dryRun, no mutation)",
              { name: args.name || "(none)" },
            );
            const handle = await context.writeResource(
              "wouldAffect",
              instanceName,
              {
                op: "setActive",
                name: args.name,
                action,
                before: currentActive,
                after,
                changed,
                checkResult: null,
                refused,
                dryRun: true,
                retrievedAt: new Date().toISOString(),
              },
            );
            return { dataHandles: [handle] };
          }

          if (refused) {
            throw new Error(
              `Refusing to SETACTIVE "${args.name}": ${refused}`,
            );
          }

          if (!changed) {
            const handle = await context.writeResource(
              "applied",
              instanceName,
              {
                op: "setActive",
                name: args.name,
                action,
                before: currentActive,
                after,
                changed: false,
                checkResult: null,
                serverResponse: null,
                retrievedAt: new Date().toISOString(),
              },
            );
            return { dataHandles: [handle] };
          }

          context.logger.info("Setting active sieve script to {name}", {
            name: args.name || "(none)",
          });
          let term: TerminalResponse;
          try {
            term = await cmdSetActive(transport, args.name);
          } catch (err) {
            await context.writeResource("applied", instanceName, {
              op: "setActive",
              name: args.name,
              action,
              before: currentActive,
              after,
              changed: false,
              checkResult: null,
              serverResponse: null,
              error: err instanceof Error ? err.message : String(err),
              retrievedAt: new Date().toISOString(),
            });
            throw err;
          }
          const handle = await context.writeResource("applied", instanceName, {
            op: "setActive",
            name: args.name,
            action,
            before: currentActive,
            after,
            changed: true,
            checkResult: null,
            serverResponse: toServerResponse(term),
            retrievedAt: new Date().toISOString(),
          });
          return { dataHandles: [handle] };
        } finally {
          await cleanup(transport);
        }
      },
    },
    deleteScript: {
      description:
        "Delete a Sieve script (DELETESCRIPT). REFUSES to delete the " +
        "currently active script -- deactivate it first via setActive. " +
        "dryRun defaults to true. Idempotent: deleting a script that no " +
        "longer exists is a recorded no-op, not an error.",
      arguments: z.object({
        name: z.string().min(1).describe("Script name to delete"),
        dryRun: z.boolean().default(true).describe(
          "true (default): preview only, zero mutation. false: mutate.",
        ),
      }),
      execute: async (
        args: { name: string; dryRun?: boolean; _transport?: ClientFactory },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        validateScriptName(args.name);
        const dryRun = args.dryRun ?? true;
        const cfg = context.globalArgs;
        const transport = (args._transport ?? defaultTransportFactory)(cfg);
        const instanceName = `delete:${scriptSlug(args.name)}`;
        try {
          await sieveConnect(transport, cfg);
          const scripts = await cmdListScripts(transport);
          const entry = scripts.find((s) => s.name === args.name);
          const exists = Boolean(entry);
          const before = entry
            ? await cmdGetScript(transport, args.name)
            : null;
          const refused = entry?.active
            ? `"${args.name}" is the active script -- deactivate it first ` +
              "(setActive) before deleting"
            : null;
          const changed = exists && !refused;

          if (dryRun) {
            context.logger.info(
              "Previewed deleteScript for {name} (dryRun, no mutation)",
              { name: args.name },
            );
            const handle = await context.writeResource(
              "wouldAffect",
              instanceName,
              {
                op: "deleteScript",
                name: args.name,
                action: "delete",
                before,
                after: null,
                changed,
                checkResult: null,
                refused,
                dryRun: true,
                retrievedAt: new Date().toISOString(),
              },
            );
            return { dataHandles: [handle] };
          }

          if (refused) {
            throw new Error(
              `Refusing to DELETESCRIPT "${args.name}": ${refused}`,
            );
          }

          if (!changed) {
            const handle = await context.writeResource(
              "applied",
              instanceName,
              {
                op: "deleteScript",
                name: args.name,
                action: "delete",
                before,
                after: null,
                changed: false,
                checkResult: null,
                serverResponse: null,
                retrievedAt: new Date().toISOString(),
              },
            );
            return { dataHandles: [handle] };
          }

          context.logger.info("Deleting sieve script {name}", {
            name: args.name,
          });
          let term: TerminalResponse;
          try {
            term = await cmdDeleteScript(transport, args.name);
          } catch (err) {
            await context.writeResource("applied", instanceName, {
              op: "deleteScript",
              name: args.name,
              action: "delete",
              before,
              after: null,
              changed: false,
              checkResult: null,
              serverResponse: null,
              error: err instanceof Error ? err.message : String(err),
              retrievedAt: new Date().toISOString(),
            });
            throw err;
          }
          const handle = await context.writeResource("applied", instanceName, {
            op: "deleteScript",
            name: args.name,
            action: "delete",
            before,
            after: null,
            changed: true,
            checkResult: null,
            serverResponse: toServerResponse(term),
            retrievedAt: new Date().toISOString(),
          });
          return { dataHandles: [handle] };
        } finally {
          await cleanup(transport);
        }
      },
    },
  },
};
