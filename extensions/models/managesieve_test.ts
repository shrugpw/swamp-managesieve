/**
 * Unit tests for the @shrug/managesieve model.
 *
 * Every test injects a synthetic scripted transport through the
 * `_transport` seam (or, for the lowest-level framing tests, exercises the
 * pure encode/parse helpers directly) -- no live ManageSieve server is ever
 * contacted. All fixtures are depersonalized: hostnames/users use
 * example.com / RFC 2606 reserved domains, never real mailbox contents.
 *
 * @module
 */
import { assertEquals, assertRejects, assertThrows } from "jsr:@std/assert@1";
import {
  buildCommandBytes,
  buildSaslPlainInitialResponse,
  type ByteConn,
  type ByteReader,
  bytesToBase64,
  type CheckOutcome,
  type ClientFactory,
  cmdCheckScript,
  cmdDeleteScript,
  cmdGetScript,
  cmdListScripts,
  cmdLogout,
  cmdPutScript,
  cmdSetActive,
  defaultTransportFactory,
  dequoteIfQuoted,
  describeTerm,
  digestHex,
  encodeLiteral,
  LineReader,
  MAX_LINE_BYTES,
  model,
  parseCapabilityLine,
  parseScriptLine,
  readCapabilities,
  readLogicalLine,
  sanitizeServerText,
  scriptSlug,
  sieveConnect,
  type SieveTransport,
  splitLines,
  type TerminalResponse,
  type TransportDeps,
  tryParseTerminal,
  validateScriptName,
  withTimeout,
} from "./managesieve.ts";

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

const enc = new TextEncoder();

/** Join wire lines with CRLF, adding a trailing CRLF after the last one too. */
function wireLines(...lines: string[]): Uint8Array {
  return enc.encode(lines.join("\r\n") + "\r\n");
}

/** RFC 5804 server literal-s2c framing: `{n}\r\n<n raw bytes>`. */
function serverLiteral(s: string): string {
  return `{${enc.encode(s).length}}\r\n${s}`;
}

const PRE_TLS_CAPS = [
  '"IMPLEMENTATION" "Test ManageSieved v1"',
  '"SASL" ""',
  '"SIEVE" "fileinto vacation"',
  '"STARTTLS"',
];
const POST_TLS_CAPS = [
  '"IMPLEMENTATION" "Test ManageSieved v1"',
  '"SASL" "PLAIN"',
  '"SIEVE" "fileinto vacation"',
];

/**
 * A synthetic scripted transport. `preTls` is drained by readLine/readExact
 * until {@link startTls} is called, at which point -- mirroring the real
 * transport's injection-safety contract -- any unread bytes in `preTls` are
 * discarded and all subsequent reads come from `postTls`.
 */
class FakeTransport implements SieveTransport {
  writes: Uint8Array[] = [];
  startTlsCalls: string[] = [];
  closed = false;
  #buf: Uint8Array;
  #post: Uint8Array;

  constructor(preTls: Uint8Array, postTls: Uint8Array = new Uint8Array(0)) {
    this.#buf = preTls;
    this.#post = postTls;
  }

  connect(): Promise<void> {
    return Promise.resolve();
  }

  write(data: Uint8Array): Promise<void> {
    this.writes.push(data);
    return Promise.resolve();
  }

  readLine(): Promise<string> {
    const idx = this.#buf.indexOf(0x0a);
    if (idx === -1) {
      throw new Error(
        "FakeTransport: scripted buffer exhausted while reading a line",
      );
    }
    let end = idx;
    if (end > 0 && this.#buf[end - 1] === 0x0d) end--;
    const text = new TextDecoder().decode(this.#buf.subarray(0, end));
    this.#buf = this.#buf.slice(idx + 1);
    return Promise.resolve(text);
  }

  readExact(n: number): Promise<Uint8Array> {
    if (this.#buf.length < n) {
      throw new Error(
        `FakeTransport: scripted buffer exhausted (wanted ${n}, have ${this.#buf.length})`,
      );
    }
    const out = this.#buf.slice(0, n);
    this.#buf = this.#buf.slice(n);
    return Promise.resolve(out);
  }

  startTls(hostname: string): Promise<void> {
    this.startTlsCalls.push(hostname);
    // Discard whatever remains unread in the plaintext-era buffer -- this
    // is the behavior under test for the "STARTTLS plaintext-injection
    // guard" scenario below.
    this.#buf = this.#post;
    return Promise.resolve();
  }

  close(): Promise<void> {
    this.closed = true;
    return Promise.resolve();
  }
}

/** All bytes a successful connect/handshake consumes, with the caller's command response appended to the post-TLS stream. */
function handshakeBytes(...postAuthLines: string[]): {
  pre: Uint8Array;
  post: Uint8Array;
} {
  const pre = wireLines(...PRE_TLS_CAPS, "OK", "OK");
  const post = wireLines(...POST_TLS_CAPS, "OK", "OK", ...postAuthLines);
  return { pre, post };
}

const CFG = {
  host: "sieve.example.com",
  port: 4190,
  user: "user@example.net",
  password: "unused-in-tests",
  tlsRejectUnauthorized: true,
  allowInsecure: false,
  // FakeTransport implements readLine itself (no LineReader), so this value
  // is never consulted by the transport-injected tests; it only has to
  // satisfy the GlobalArgs type.
  timeoutMs: 5000,
};

function transportFactory(t: FakeTransport): ClientFactory {
  return () => t;
}

/** Collect the writeResource calls a method makes. */
function makeContext() {
  const writes: Array<
    { spec: string; name: string; data: Record<string, unknown> }
  > = [];
  const context = {
    globalArgs: CFG,
    logger: { info() {}, warning() {} },
    writeResource: (
      spec: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      writes.push({ spec, name, data });
      return Promise.resolve({ name });
    },
  };
  return { context, writes };
}

// ---------------------------------------------------------------------------
// Literal / command framing -- the core injection-safety surface
// ---------------------------------------------------------------------------

Deno.test("encodeLiteral frames a plain value as {n+}\\r\\n<bytes>", () => {
  const out = encodeLiteral("foo");
  assertEquals(new TextDecoder().decode(out), "{3+}\r\nfoo");
});

Deno.test("encodeLiteral: byte count is exact for multi-byte UTF-8", () => {
  // "caf\u00e9" ("cafe" with an accented e), written with a \u escape to
  // keep this source file pure ASCII: 4 chars, 5 UTF-8 bytes (the accented
  // e is 2 bytes).
  const out = encodeLiteral("caf\u00e9");
  const text = new TextDecoder().decode(out);
  assertEquals(text, "{5+}\r\ncaf\u00e9");
});

Deno.test("encodeLiteral: empty string is a valid zero-length literal", () => {
  const out = encodeLiteral("");
  assertEquals(new TextDecoder().decode(out), "{0+}\r\n");
});

Deno.test("buildCommandBytes: no-arg command is just KEYWORD CRLF", () => {
  const out = buildCommandBytes("LOGOUT");
  assertEquals(new TextDecoder().decode(out), "LOGOUT\r\n");
});

Deno.test("buildCommandBytes: a hostile script name cannot inject a second command", () => {
  // A name that LOOKS like it could terminate the literal early and smuggle
  // a second command: embedded CRLF, quotes, and a bogus literal header.
  const hostile = 'evil" {0+}\r\nDELETESCRIPT "other';
  const out = buildCommandBytes("GETSCRIPT", [hostile]);
  const text = new TextDecoder().decode(out);
  const hostileBytes = new TextEncoder().encode(hostile).length;
  // The wire form must be exactly: GETSCRIPT {n+}\r\n<hostile bytes verbatim>\r\n
  assertEquals(text, `GETSCRIPT {${hostileBytes}+}\r\n${hostile}\r\n`);
  // Critically, the ANNOUNCED length matches the ACTUAL payload length --
  // a server reads exactly that many bytes and therefore can never
  // misinterpret the embedded CRLF/quote/brace content as a new command.
  const announced = /\{(\d+)\+\}/.exec(text)!;
  assertEquals(Number(announced[1]), hostileBytes);
});

Deno.test("buildCommandBytes: multi-line script text round-trips byte-for-byte", () => {
  const script =
    'require ["fileinto"];\r\nif true {\r\n  fileinto "INBOX";\r\n}\r\n';
  const out = buildCommandBytes("PUTSCRIPT", ["myscript", script]);
  const text = new TextDecoder().decode(out);
  // The script's own embedded CRLFs must appear verbatim inside the literal,
  // not be treated as command-line terminators.
  const scriptBytes = new TextEncoder().encode(script).length;
  assertEquals(
    text,
    `PUTSCRIPT {8+}\r\nmyscript {${scriptBytes}+}\r\n${script}\r\n`,
  );
});

Deno.test("buildSaslPlainInitialResponse encodes authzid NUL authcid NUL passwd", () => {
  const b64 = buildSaslPlainInitialResponse("user@example.net", "s3cr3t");
  const decoded = new TextDecoder().decode(
    Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)),
  );
  const parts = decoded.split("\u0000");
  assertEquals(parts, ["", "user@example.net", "s3cr3t"]);
});

Deno.test("bytesToBase64 round-trips through atob", () => {
  const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
  const b64 = bytesToBase64(bytes);
  const back = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  assertEquals(back, bytes);
});

// ---------------------------------------------------------------------------
// Response parsing (pure helpers)
// ---------------------------------------------------------------------------

Deno.test("tryParseTerminal parses OK/NO/BYE with optional code and text", () => {
  assertEquals(tryParseTerminal("OK"), { tag: "OK", code: null, text: null });
  assertEquals(
    tryParseTerminal('NO (NONEXISTENT) "There is no script by that name"'),
    { tag: "NO", code: "NONEXISTENT", text: "There is no script by that name" },
  );
  assertEquals(
    tryParseTerminal('BYE "Too many failed authentication attempts"'),
    { tag: "BYE", code: null, text: "Too many failed authentication attempts" },
  );
  assertEquals(tryParseTerminal('OK (WARNINGS) "line 8: ignored"'), {
    tag: "OK",
    code: "WARNINGS",
    text: "line 8: ignored",
  });
});

Deno.test("tryParseTerminal returns null for a data line", () => {
  assertEquals(tryParseTerminal('"summer_script"'), null);
  assertEquals(tryParseTerminal('"main_script" ACTIVE'), null);
  // A name that is a PREFIX of a keyword, not the bare keyword, must not match.
  assertEquals(tryParseTerminal("Nothing"), null);
  assertEquals(tryParseTerminal("OKish"), null);
});

Deno.test("describeTerm renders a short diagnostic string", () => {
  assertEquals(
    describeTerm({ tag: "NO", code: "ACTIVE", text: "nope" }),
    "NO (ACTIVE) nope",
  );
  assertEquals(describeTerm({ tag: "OK", code: null, text: null }), "OK");
});

Deno.test("parseScriptLine strips quotes and detects ACTIVE", () => {
  assertEquals(parseScriptLine('"summer_script"'), {
    name: "summer_script",
    active: false,
  });
  assertEquals(parseScriptLine('"main_script" ACTIVE'), {
    name: "main_script",
    active: true,
  });
  assertEquals(parseScriptLine('clever"script ACTIVE'), {
    name: 'clever"script',
    active: true,
  });
});

Deno.test("parseCapabilityLine handles quoted name+value, name-only, and the literal fallback", () => {
  assertEquals(parseCapabilityLine('"SASL" "PLAIN SCRAM-SHA-1"'), {
    name: "SASL",
    value: "PLAIN SCRAM-SHA-1",
  });
  assertEquals(parseCapabilityLine('"STARTTLS"'), {
    name: "STARTTLS",
    value: null,
  });
  // Fallback (documented limitation): a literal-resolved, unquoted line.
  assertEquals(parseCapabilityLine("VERSION 1.0"), {
    name: "VERSION",
    value: "1.0",
  });
});

Deno.test("dequoteIfQuoted unescapes backslash pairs; leaves bare text alone", () => {
  assertEquals(dequoteIfQuoted('"a\\"b"'), 'a"b');
  assertEquals(dequoteIfQuoted("bare"), "bare");
});

Deno.test("splitLines trims and drops empties from a multi-line literal", () => {
  assertEquals(splitLines("line 2: Syntax error\r\n\r\nline 5: also bad\n"), [
    "line 2: Syntax error",
    "line 5: also bad",
  ]);
});

// ---------------------------------------------------------------------------
// Validation + slug helpers
// ---------------------------------------------------------------------------

Deno.test("validateScriptName rejects empty, oversized, and control-char names", () => {
  assertThrows(() => validateScriptName(""));
  validateScriptName("", { allowEmpty: true }); // does not throw
  assertThrows(() => validateScriptName("a".repeat(129)));
  assertThrows(() => validateScriptName("has\x1fcontrol"));
  assertThrows(() => validateScriptName("has\u2028separator"));
  validateScriptName("perfectly-fine_name.v2"); // does not throw
});

Deno.test("scriptSlug is collision-free for distinct names", () => {
  const a = scriptSlug("Team/Alpha");
  const b = scriptSlug("Team.Alpha");
  assertEquals(a === b, false);
  assertEquals(scriptSlug("plain-name_1.2"), "plain-name_1.2");
});

Deno.test("digestHex is deterministic and content-sensitive", async () => {
  const h1 = await digestHex("if true { stop; }");
  const h2 = await digestHex("if true { stop; }");
  const h3 = await digestHex("if false { stop; }");
  assertEquals(h1, h2);
  assertEquals(h1 === h3, false);
  assertEquals(h1.length, 64);
});

// ---------------------------------------------------------------------------
// readLogicalLine / readCapabilities -- literal resolution over a transport
// ---------------------------------------------------------------------------

Deno.test("readLogicalLine resolves a server literal inline, including a trailing suffix", async () => {
  const t = new FakeTransport(
    wireLines(serverLiteral('clever"script') + " ACTIVE"),
  );
  const line = await readLogicalLine(t);
  assertEquals(line.text, 'clever"script ACTIVE');
  // A pure-literal data line never begins with an OK/NO/BYE atom -> data.
  assertEquals(line.isTerminal, false);
});

Deno.test("readLogicalLine preserves embedded CRLFs inside a literal (multi-line script)", async () => {
  const script = '#comment\r\nreject "hi";\r\n';
  const t = new FakeTransport(wireLines(serverLiteral(script)));
  const line = await readLogicalLine(t);
  assertEquals(line.text, script);
  assertEquals(line.isTerminal, false);
});

Deno.test("readLogicalLine: a terminal line whose text is a literal still parses as terminal", async () => {
  // RFC 5804 2.8: NO (NONEXISTENT) {31}\r\n<31 bytes>. The head begins with
  // a bare NO atom, so it is framed terminal even though its human text
  // arrives as a literal.
  const t = new FakeTransport(
    wireLines(
      "NO (NONEXISTENT) " + serverLiteral("There is no script by that name"),
    ),
  );
  const line = await readLogicalLine(t);
  assertEquals(line.isTerminal, true);
  const term = tryParseTerminal(line.text);
  assertEquals(term?.tag, "NO");
  assertEquals(term?.code, "NONEXISTENT");
  assertEquals(term?.text, "There is no script by that name");
});

Deno.test("readLogicalLine: MS-2 rejects an over-cap server literal before allocating", async () => {
  // Declare a 10-digit octet count well past MAX_LITERAL_BYTES. The guard
  // must fire on the {n} header; FakeTransport.readExact is never reached
  // (it would otherwise throw a different 'buffer exhausted' error).
  const t = new FakeTransport(wireLines("{9999999999}"));
  await assertRejects(
    () => readLogicalLine(t),
    Error,
    "exceeds the",
  );
});

Deno.test("readCapabilities collects lines until the terminal OK", async () => {
  const t = new FakeTransport(wireLines(...PRE_TLS_CAPS, "OK"));
  const caps = await readCapabilities(t);
  assertEquals(caps.get("SASL"), "");
  assertEquals(caps.get("STARTTLS"), "");
  assertEquals(caps.has("SIEVE"), true);
});

Deno.test("readCapabilities throws on a NO/BYE greeting", async () => {
  const t = new FakeTransport(wireLines('BYE "overloaded, try later"'));
  await assertRejects(() => readCapabilities(t), Error, "overloaded");
});

// ---------------------------------------------------------------------------
// LineReader -- the STARTTLS discard-on-upgrade contract, tested directly
// ---------------------------------------------------------------------------

class QueueByteReader implements ByteReader {
  constructor(private chunks: Uint8Array[]) {}
  read(p: Uint8Array): Promise<number | null> {
    const chunk = this.chunks.shift();
    if (!chunk) return Promise.resolve(null);
    p.set(chunk.subarray(0, Math.min(p.length, chunk.length)));
    return Promise.resolve(Math.min(p.length, chunk.length));
  }
}

Deno.test("LineReader.setConn discards buffered bytes from the old connection", async () => {
  // Deliver "OK\r\nINJECTED" in ONE read -- exactly the scenario where an
  // active MITM paces an injection into the same TCP segment as the
  // legitimate response.
  const reader = new LineReader(
    new QueueByteReader([new TextEncoder().encode("OK\r\nINJECTED\r\n")]),
  );
  assertEquals(await reader.readLine(), "OK");
  // At this point "INJECTED" is sitting in the buffer. Swapping the
  // connection (as startTls() does) must discard it, not carry it forward.
  reader.setConn(new QueueByteReader([new TextEncoder().encode("SAFE\r\n")]));
  assertEquals(await reader.readLine(), "SAFE");
});

/** A ByteReader whose read() never resolves -- models a stalled server. */
class StallingByteReader implements ByteReader {
  read(_p: Uint8Array): Promise<number | null> {
    return new Promise<number | null>(() => {});
  }
}

/** A ByteReader that endlessly yields non-LF bytes -- models a no-terminator flood. */
class FloodByteReader implements ByteReader {
  read(p: Uint8Array): Promise<number | null> {
    p.fill(0x41); // 'A', never 0x0a
    return Promise.resolve(p.length);
  }
}

Deno.test("MS-1: LineReader.readLine rejects on a per-read timeout when the server stalls", async () => {
  const reader = new LineReader(new StallingByteReader(), 20);
  const started = Date.now();
  await assertRejects(() => reader.readLine(), Error, "timed out after 20 ms");
  // Sanity: it returned promptly (near the deadline), not after some long hang.
  assertEquals(Date.now() - started < 2000, true);
});

Deno.test("MS-1: timeoutMs=0 disables the deadline (read still resolves normally)", async () => {
  const reader = new LineReader(
    new QueueByteReader([new TextEncoder().encode("OK\r\n")]),
    0,
  );
  assertEquals(await reader.readLine(), "OK");
});

Deno.test("MS-1: withTimeout rejects after the deadline and a late settle raises no unhandled rejection", async () => {
  let resolveLate: (v: number) => void = () => {};
  const late = new Promise<number>((r) => {
    resolveLate = r;
  });
  await assertRejects(
    () => withTimeout(late, 10, "unit op"),
    Error,
    "unit op timed out after 10 ms",
  );
  // Settle the original promise AFTER the timeout already fired. withTimeout
  // attached a resolution handler, so this must not surface as an unhandled
  // rejection or throw. Give the microtask queue a tick to flush.
  resolveLate(1);
  await new Promise((r) => setTimeout(r, 0));
});

Deno.test("MS-1: withTimeout runs the onTimeout hook (e.g. to close the socket)", async () => {
  let closed = false;
  await assertRejects(
    () =>
      withTimeout(
        new Promise<void>(() => {}),
        10,
        "op",
        () => {
          closed = true;
        },
      ),
    Error,
  );
  assertEquals(closed, true);
});

Deno.test("MS-2: LineReader.readLine aborts a no-terminator flood past the byte cap", async () => {
  const reader = new LineReader(new FloodByteReader(), 0);
  await assertRejects(
    () => reader.readLine(),
    Error,
    `exceeded ${MAX_LINE_BYTES} bytes`,
  );
});

// ---------------------------------------------------------------------------
// sieveConnect -- handshake, STARTTLS gating, AUTHENTICATE
// ---------------------------------------------------------------------------

Deno.test("sieveConnect: happy path performs STARTTLS then AUTHENTICATE PLAIN", async () => {
  const { pre, post } = handshakeBytes();
  const t = new FakeTransport(pre, post);
  await sieveConnect(t, CFG);
  assertEquals(t.startTlsCalls, [CFG.host]);
  // Command 1 (plaintext): STARTTLS. Command 2 (post-TLS): AUTHENTICATE.
  const cmd1 = new TextDecoder().decode(t.writes[0]);
  const cmd2 = new TextDecoder().decode(t.writes[1]);
  assertEquals(cmd1, "STARTTLS\r\n");
  assertEquals(cmd2.startsWith("AUTHENTICATE {5+}\r\nPLAIN {"), true);
});

Deno.test("sieveConnect: refuses to authenticate when STARTTLS is not advertised", async () => {
  const pre = wireLines(
    '"IMPLEMENTATION" "Test"',
    '"SASL" "PLAIN"',
    "OK",
  );
  const t = new FakeTransport(pre);
  await assertRejects(
    () => sieveConnect(t, CFG),
    Error,
    "does not advertise STARTTLS",
  );
});

Deno.test("sieveConnect: allowInsecure=true permits skipping STARTTLS", async () => {
  const pre = wireLines(
    '"IMPLEMENTATION" "Test"',
    '"SASL" "PLAIN"',
    "OK",
    "OK", // AUTHENTICATE response
  );
  const t = new FakeTransport(pre);
  await sieveConnect(t, { ...CFG, allowInsecure: true });
  assertEquals(t.startTlsCalls, []);
});

Deno.test("sieveConnect: refuses to authenticate when SASL PLAIN is not advertised post-TLS", async () => {
  const pre = wireLines(...PRE_TLS_CAPS, "OK", "OK");
  const post = wireLines(
    '"IMPLEMENTATION" "Test"',
    '"SASL" "GSSAPI"',
    "OK",
  );
  const t = new FakeTransport(pre, post);
  await assertRejects(
    () => sieveConnect(t, CFG),
    Error,
    "does not advertise SASL PLAIN",
  );
});

Deno.test("sieveConnect: AUTHENTICATE failure (NO) surfaces the server's reason", async () => {
  const { pre } = handshakeBytes();
  const post = wireLines(
    ...POST_TLS_CAPS,
    "OK",
    'NO "Authentication failed"',
  );
  const t = new FakeTransport(pre, post);
  await assertRejects(
    () => sieveConnect(t, CFG),
    Error,
    "Authentication failed",
  );
});

Deno.test("sieveConnect: STARTTLS plaintext-injection guard -- leftover pre-TLS bytes are never consulted", async () => {
  // After the legitimate STARTTLS "OK", the pre-TLS buffer carries BOGUS
  // injected capabilities that advertise only GSSAPI (no PLAIN). If
  // sieveConnect (or the transport) ever read capabilities from this
  // leftover plaintext data instead of the real post-TLS stream, the
  // SASL-PLAIN check below would fail. It must succeed, using `post`.
  const pre = wireLines(
    ...PRE_TLS_CAPS,
    "OK",
    "OK", // STARTTLS OK
    '"SASL" "GSSAPI"', // injected, must be discarded
    "OK",
  );
  const { post } = handshakeBytes();
  const t = new FakeTransport(pre, post);
  await sieveConnect(t, CFG); // must not throw
  assertEquals(t.startTlsCalls, [CFG.host]);
});

// ---------------------------------------------------------------------------
// Command-level protocol functions (cmd*)
// ---------------------------------------------------------------------------

Deno.test("cmdListScripts parses quoted and literal entries, with ACTIVE on one", async () => {
  const t = new FakeTransport(
    wireLines(
      '"summer_script"',
      '"vacation_script"',
      serverLiteral('clever"script'),
      '"main_script" ACTIVE',
      "OK",
    ),
  );
  const scripts = await cmdListScripts(t);
  assertEquals(scripts, [
    { name: "summer_script", active: false },
    { name: "vacation_script", active: false },
    { name: 'clever"script', active: false },
    { name: "main_script", active: true },
  ]);
});

Deno.test("cmdListScripts throws on BYE", async () => {
  const t = new FakeTransport(wireLines('BYE "server shutting down"'));
  await assertRejects(() => cmdListScripts(t), Error, "server shutting down");
});

Deno.test("cmdGetScript returns literal content, then throws NONEXISTENT for a missing script", async () => {
  const content = 'require ["fileinto"];\r\nfileinto "INBOX";\r\n';
  const t = new FakeTransport(wireLines(serverLiteral(content), "OK"));
  assertEquals(await cmdGetScript(t, "myscript"), content);

  const t2 = new FakeTransport(
    wireLines('NO (NONEXISTENT) "There is no script by that name"'),
  );
  await assertRejects(
    () => cmdGetScript(t2, "ghost"),
    Error,
    "NONEXISTENT",
  );
});

Deno.test("MS-3: cmdGetScript returns a literal body that STARTS WITH no/bye verbatim (framing, not content)", async () => {
  // Each of these bodies, pre-fix, would have been regex-matched as a
  // terminal NO/BYE and thrown. Framing resolves it to data every time.
  for (
    const body of ['no "really" this is sieve\r\n', "bye now;\r\n", "ok\r\n"]
  ) {
    const t = new FakeTransport(wireLines(serverLiteral(body), "OK"));
    assertEquals(await cmdGetScript(t, "weird"), body);
  }
});

Deno.test("MS-3: putScript before/after diff is correct for a live body starting with no/bye", async () => {
  // Live script body begins with "no" -- the pre-fix misparse broke the
  // PHASE-1 GETSCRIPT 'before' read, corrupting the idempotency diff on the
  // gated-write path. With framing, before===after and the call is a no-op.
  const body = 'no "spam";\r\nstop;\r\n';
  const { pre, post } = handshakeBytes(
    '"filter" ACTIVE', // LISTSCRIPTS: found, active
    "OK",
    serverLiteral(body), // GETSCRIPT 'before'
    "OK",
    "OK", // CHECKSCRIPT ok
  );
  const t = new FakeTransport(pre, post);
  const { context, writes } = makeContext();
  await model.methods.putScript.execute(
    {
      name: "filter",
      text: body,
      dryRun: false,
      _transport: transportFactory(t),
    },
    context,
  );
  // Correct diff: identical body -> recorded no-op, zero PUTSCRIPT sent.
  assertEquals(writes[0].spec, "applied");
  assertEquals(writes[0].data.before, body);
  assertEquals(writes[0].data.changed, false);
  const sent = t.writes.map((b) => new TextDecoder().decode(b));
  assertEquals(sent.some((s) => s.startsWith("PUTSCRIPT")), false);
});

Deno.test("cmdCheckScript: ok, ok-with-warnings, and failing with multi-line errors", async () => {
  const tOk = new FakeTransport(wireLines("OK"));
  assertEquals(await cmdCheckScript(tOk, "stop;"), {
    ok: true,
    errors: [],
    warnings: [],
    code: null,
  });

  const tWarn = new FakeTransport(
    wireLines('OK (WARNINGS) "line 8: ignored action"'),
  );
  assertEquals(await cmdCheckScript(tWarn, "stop;"), {
    ok: true,
    errors: [],
    warnings: ["line 8: ignored action"],
    code: "WARNINGS",
  });

  const tFail = new FakeTransport(
    wireLines(
      "NO " + serverLiteral("line 2: syntax error\r\nline 5: also bad"),
    ),
  );
  const result: CheckOutcome = await cmdCheckScript(tFail, "garbage {{{");
  assertEquals(result.ok, false);
  assertEquals(result.errors, ["line 2: syntax error", "line 5: also bad"]);
});

Deno.test("cmdPutScript/cmdSetActive/cmdDeleteScript succeed on OK and throw with context on NO", async () => {
  const tPut = new FakeTransport(wireLines("OK"));
  const r1: TerminalResponse = await cmdPutScript(tPut, "n", "stop;");
  assertEquals(r1.tag, "OK");

  const tActive = new FakeTransport(wireLines("OK"));
  await cmdSetActive(tActive, "n");

  const tDel = new FakeTransport(
    wireLines('NO (ACTIVE) "You may not delete an active script"'),
  );
  await assertRejects(
    () => cmdDeleteScript(tDel, "n"),
    Error,
    "You may not delete an active script",
  );
});

Deno.test("cmdLogout never throws even if the server closes immediately", async () => {
  class ImmediateCloseTransport extends FakeTransport {
    override readLine(): Promise<string> {
      throw new Error("connection closed");
    }
  }
  const t = new ImmediateCloseTransport(new Uint8Array(0));
  await cmdLogout(t); // must not throw
});

// ---------------------------------------------------------------------------
// Model method execute() -- full read methods
// ---------------------------------------------------------------------------

Deno.test("listScripts method writes a scripts resource", async () => {
  const { pre, post } = handshakeBytes(
    '"summer_script"',
    '"main_script" ACTIVE',
    "OK",
  );
  const t = new FakeTransport(pre, post);
  const { context, writes } = makeContext();
  const result = await model.methods.listScripts.execute(
    { _transport: transportFactory(t) },
    context,
  );
  assertEquals(result.dataHandles, [{ name: "list" }]);
  assertEquals(writes[0].spec, "scripts");
  assertEquals(writes[0].data.count, 2);
  assertEquals(t.closed, true);
});

Deno.test("getScript method writes a script resource keyed by name slug", async () => {
  const content = "stop;\r\n";
  const { pre, post } = handshakeBytes(serverLiteral(content), "OK");
  const t = new FakeTransport(pre, post);
  const { context, writes } = makeContext();
  await model.methods.getScript.execute(
    { name: "my/script", _transport: transportFactory(t) },
    context,
  );
  assertEquals(writes[0].name, `script:${scriptSlug("my/script")}`);
  assertEquals(writes[0].data.content, content);
});

Deno.test("getActive method reports null when no script is active", async () => {
  const { pre, post } = handshakeBytes('"only_script"', "OK");
  const t = new FakeTransport(pre, post);
  const { context, writes } = makeContext();
  await model.methods.getActive.execute(
    { _transport: transportFactory(t) },
    context,
  );
  assertEquals(writes[0].data.name, null);
});

Deno.test("checkScript method surfaces a failing validation without ever calling PUTSCRIPT", async () => {
  const { pre, post } = handshakeBytes(
    "NO " + serverLiteral("line 1: syntax error"),
  );
  const t = new FakeTransport(pre, post);
  const { context, writes } = makeContext();
  await model.methods.checkScript.execute(
    { text: "garbage {{{", _transport: transportFactory(t) },
    context,
  );
  assertEquals(writes[0].data.ok, false);
  assertEquals(writes[0].data.errors, ["line 1: syntax error"]);
  // Only ONE command was ever sent after AUTHENTICATE: CHECKSCRIPT (the 4th
  // write is the best-effort LOGOUT every method's cleanup path sends).
  assertEquals(t.writes.length, 4);
  assertEquals(
    new TextDecoder().decode(t.writes[2]).startsWith("CHECKSCRIPT"),
    true,
  );
});

// ---------------------------------------------------------------------------
// putScript -- dryRun preview, apply, idempotency, checkscript-blocks-write
// ---------------------------------------------------------------------------

Deno.test("putScript: dryRun=true preview computes a real CHECKSCRIPT result with zero mutation", async () => {
  // LISTSCRIPTS (not found) -> CHECKSCRIPT ok.
  const { pre, post } = handshakeBytes("OK", "OK");
  const t = new FakeTransport(pre, post);
  const { context, writes } = makeContext();
  const result = await model.methods.putScript.execute(
    { name: "new-script", text: "stop;", _transport: transportFactory(t) },
    context,
  );
  assertEquals(result.dataHandles, [{ name: "put:new-script" }]);
  const w = writes[0];
  assertEquals(w.spec, "wouldAffect");
  assertEquals(w.data.before, null);
  assertEquals(w.data.after, "stop;");
  assertEquals(w.data.changed, true);
  assertEquals((w.data.checkResult as { ok: boolean }).ok, true);
  assertEquals(w.data.refused, null);
  // No PUTSCRIPT was ever sent in dryRun mode.
  const sentKeywords = t.writes.slice(2).map((b) =>
    new TextDecoder().decode(b).split(" ")[0].split("\r")[0]
  );
  assertEquals(sentKeywords.includes("PUTSCRIPT"), false);
});

Deno.test("putScript: checkScript failure BLOCKS putscript, both in dryRun and dryRun=false", async () => {
  // dryRun=true: LISTSCRIPTS (not found), CHECKSCRIPT (fails).
  {
    const { pre, post } = handshakeBytes(
      "OK",
      "NO " + serverLiteral("line 1: syntax error"),
    );
    const t = new FakeTransport(pre, post);
    const { context, writes } = makeContext();
    await model.methods.putScript.execute(
      {
        name: "bad",
        text: "garbage {{{",
        dryRun: true,
        _transport: transportFactory(t),
      },
      context,
    );
    assertEquals(writes[0].data.changed, false);
    assertEquals(
      (writes[0].data.refused as string).includes("CHECKSCRIPT rejected"),
      true,
    );
  }
  // dryRun=false: must THROW (refuse), and PUTSCRIPT must never be sent.
  {
    const { pre, post } = handshakeBytes(
      "OK",
      "NO " + serverLiteral("line 1: syntax error"),
    );
    const t = new FakeTransport(pre, post);
    const { context } = makeContext();
    await assertRejects(
      () =>
        model.methods.putScript.execute(
          {
            name: "bad",
            text: "garbage {{{",
            dryRun: false,
            _transport: transportFactory(t),
          },
          context,
        ),
      Error,
      "Refusing to PUTSCRIPT",
    );
    const sent = t.writes.map((b) => new TextDecoder().decode(b));
    assertEquals(sent.some((s) => s.startsWith("PUTSCRIPT")), false);
  }
});

Deno.test("putScript: dryRun=false is idempotent -- byte-identical live script sends zero PUTSCRIPT", async () => {
  const liveContent = "stop;\r\n";
  // LISTSCRIPTS finds it -> GETSCRIPT returns identical content -> CHECKSCRIPT ok.
  const { pre, post } = handshakeBytes(
    '"same" ACTIVE',
    "OK",
    serverLiteral(liveContent),
    "OK",
    "OK",
  );
  const t = new FakeTransport(pre, post);
  const { context, writes } = makeContext();
  await model.methods.putScript.execute(
    {
      name: "same",
      text: liveContent,
      dryRun: false,
      _transport: transportFactory(t),
    },
    context,
  );
  assertEquals(writes[0].spec, "applied");
  assertEquals(writes[0].data.changed, false);
  const sent = t.writes.map((b) => new TextDecoder().decode(b));
  assertEquals(sent.some((s) => s.startsWith("PUTSCRIPT")), false);
});

Deno.test("putScript: dryRun=false applies a real change and records the server response", async () => {
  // LISTSCRIPTS (not found) -> CHECKSCRIPT ok -> PUTSCRIPT OK.
  const { pre, post } = handshakeBytes("OK", "OK", "OK");
  const t = new FakeTransport(pre, post);
  const { context, writes } = makeContext();
  await model.methods.putScript.execute(
    {
      name: "new-script",
      text: "stop;",
      dryRun: false,
      _transport: transportFactory(t),
    },
    context,
  );
  assertEquals(writes[0].data.changed, true);
  assertEquals((writes[0].data.serverResponse as { tag: string }).tag, "OK");
  const sent = t.writes.map((b) => new TextDecoder().decode(b));
  assertEquals(sent.some((s) => s.startsWith("PUTSCRIPT")), true);
});

// ---------------------------------------------------------------------------
// setActive -- dryRun, idempotency, refuse-nonexistent
// ---------------------------------------------------------------------------

Deno.test("setActive: dryRun=true previews activation without mutating", async () => {
  const { pre, post } = handshakeBytes('"a"', '"b" ACTIVE', "OK");
  const t = new FakeTransport(pre, post);
  const { context, writes } = makeContext();
  await model.methods.setActive.execute(
    { name: "a", _transport: transportFactory(t) },
    context,
  );
  assertEquals(writes[0].data.before, "b");
  assertEquals(writes[0].data.after, "a");
  assertEquals(writes[0].data.changed, true);
  const sent = t.writes.map((b) => new TextDecoder().decode(b));
  assertEquals(sent.some((s) => s.startsWith("SETACTIVE")), false);
});

Deno.test("setActive: activating the already-active script is an idempotent no-op", async () => {
  const { pre, post } = handshakeBytes('"a" ACTIVE', "OK");
  const t = new FakeTransport(pre, post);
  const { context, writes } = makeContext();
  await model.methods.setActive.execute(
    { name: "a", dryRun: false, _transport: transportFactory(t) },
    context,
  );
  assertEquals(writes[0].spec, "applied");
  assertEquals(writes[0].data.changed, false);
  const sent = t.writes.map((b) => new TextDecoder().decode(b));
  assertEquals(sent.some((s) => s.startsWith("SETACTIVE")), false);
});

Deno.test("setActive: deactivating when nothing is active is an idempotent no-op", async () => {
  const { pre, post } = handshakeBytes('"a"', "OK");
  const t = new FakeTransport(pre, post);
  const { context, writes } = makeContext();
  await model.methods.setActive.execute(
    { name: "", dryRun: false, _transport: transportFactory(t) },
    context,
  );
  assertEquals(writes[0].data.changed, false);
  assertEquals(writes[0].data.before, null);
  assertEquals(writes[0].data.after, null);
});

Deno.test("setActive: refuses to activate a name LISTSCRIPTS does not report", async () => {
  const { pre, post } = handshakeBytes('"a"', "OK");
  const t = new FakeTransport(pre, post);
  const { context } = makeContext();
  await assertRejects(
    () =>
      model.methods.setActive.execute(
        {
          name: "ghost",
          dryRun: false,
          _transport: transportFactory(t),
        },
        context,
      ),
    Error,
    "Refusing to SETACTIVE",
  );
  const sent = t.writes.map((b) => new TextDecoder().decode(b));
  assertEquals(sent.some((s) => s.startsWith("SETACTIVE")), false);
});

// ---------------------------------------------------------------------------
// deleteScript -- refuse-active, idempotent-missing, apply
// ---------------------------------------------------------------------------

Deno.test("deleteScript: REFUSES to delete the currently active script (dryRun and dryRun=false)", async () => {
  // dryRun=true: shows the refusal without mutating.
  {
    const { pre, post } = handshakeBytes(
      '"a" ACTIVE',
      "OK",
      serverLiteral("stop;"),
      "OK",
    );
    const t = new FakeTransport(pre, post);
    const { context, writes } = makeContext();
    await model.methods.deleteScript.execute(
      { name: "a", _transport: transportFactory(t) },
      context,
    );
    assertEquals(writes[0].data.changed, false);
    assertEquals(
      (writes[0].data.refused as string).includes("active script"),
      true,
    );
  }
  // dryRun=false: THROWS, no DELETESCRIPT ever sent.
  {
    const { pre, post } = handshakeBytes(
      '"a" ACTIVE',
      "OK",
      serverLiteral("stop;"),
      "OK",
    );
    const t = new FakeTransport(pre, post);
    const { context } = makeContext();
    await assertRejects(
      () =>
        model.methods.deleteScript.execute(
          { name: "a", dryRun: false, _transport: transportFactory(t) },
          context,
        ),
      Error,
      "Refusing to DELETESCRIPT",
    );
    const sent = t.writes.map((b) => new TextDecoder().decode(b));
    assertEquals(sent.some((s) => s.startsWith("DELETESCRIPT")), false);
  }
});

Deno.test("deleteScript: deleting an already-absent script is an idempotent no-op, not an error", async () => {
  const { pre, post } = handshakeBytes('"other"', "OK");
  const t = new FakeTransport(pre, post);
  const { context, writes } = makeContext();
  await model.methods.deleteScript.execute(
    { name: "ghost", dryRun: false, _transport: transportFactory(t) },
    context,
  );
  assertEquals(writes[0].spec, "applied");
  assertEquals(writes[0].data.changed, false);
  assertEquals(writes[0].data.error, undefined);
});

Deno.test("deleteScript: dryRun=false deletes an inactive, existing script", async () => {
  const { pre, post } = handshakeBytes(
    '"a"',
    "OK",
    serverLiteral("stop;"),
    "OK",
    "OK",
  );
  const t = new FakeTransport(pre, post);
  const { context, writes } = makeContext();
  await model.methods.deleteScript.execute(
    { name: "a", dryRun: false, _transport: transportFactory(t) },
    context,
  );
  assertEquals(writes[0].data.changed, true);
  const sent = t.writes.map((b) => new TextDecoder().decode(b));
  assertEquals(sent.some((s) => s.startsWith("DELETESCRIPT")), true);
});

// ---------------------------------------------------------------------------
// defaultTransportFactory -- sanity (no live connection attempted)
// ---------------------------------------------------------------------------

Deno.test("defaultTransportFactory returns a transport that throws clearly before connect()", async () => {
  const t = defaultTransportFactory(CFG);
  await assertRejects(() => t.readLine(), Error, "not connected");
  await assertRejects(() => t.write(new Uint8Array(0)), Error, "not connected");
});

// ---------------------------------------------------------------------------
// MS-4: the REAL STARTTLS-discard wiring in defaultTransportFactory
// ---------------------------------------------------------------------------

/** A fake ByteConn fed by a scripted byte buffer (one chunk per read). */
class FakeByteConn implements ByteConn {
  closed = false;
  constructor(private buf: Uint8Array) {}
  read(p: Uint8Array): Promise<number | null> {
    if (this.buf.length === 0) return Promise.resolve(null);
    const n = Math.min(p.length, this.buf.length);
    p.set(this.buf.subarray(0, n));
    this.buf = this.buf.slice(n);
    return Promise.resolve(n);
  }
  write(p: Uint8Array): Promise<number> {
    return Promise.resolve(p.length);
  }
  close(): void {
    this.closed = true;
  }
}

Deno.test("MS-4: defaultTransportFactory.startTls swaps the conn AND drops pre-TLS buffered bytes (real wiring)", async () => {
  // Pre-TLS conn delivers a legit line PLUS injected trailing plaintext in
  // the SAME read. Post-TLS conn delivers the real post-upgrade data.
  const preConn = new FakeByteConn(
    new TextEncoder().encode("OK\r\nINJECTED-PLAINTEXT\r\n"),
  );
  const tlsConn = new FakeByteConn(new TextEncoder().encode("TLS-SAFE\r\n"));
  const deps: TransportDeps = {
    connect: () => Promise.resolve(preConn),
    startTls: (_conn, _hostname, _reject) => Promise.resolve(tlsConn),
  };
  // Drive the REAL transport (conn=tlsConn; reader.setConn(tlsConn)), not a
  // FakeTransport with its own hardcoded discard.
  const t = defaultTransportFactory(CFG, deps);
  await t.connect();
  assertEquals(await t.readLine(), "OK");
  // "INJECTED-PLAINTEXT" is now buffered in the LineReader. The upgrade must
  // discard it so a post-TLS read returns only genuine TLS-channel bytes.
  await t.startTls(CFG.host);
  assertEquals(await t.readLine(), "TLS-SAFE");
});

Deno.test("MS-4: startTls passes tlsRejectUnauthorized through to deps.startTls", async () => {
  const preConn = new FakeByteConn(new TextEncoder().encode("OK\r\n"));
  const tlsConn = new FakeByteConn(new TextEncoder().encode("OK\r\n"));
  let sawReject: boolean | null = null;
  const deps: TransportDeps = {
    connect: () => Promise.resolve(preConn),
    startTls: (_conn, _hostname, reject) => {
      sawReject = reject;
      return Promise.resolve(tlsConn);
    },
  };
  const t = defaultTransportFactory(
    { ...CFG, tlsRejectUnauthorized: false },
    deps,
  );
  await t.connect();
  await t.readLine();
  await t.startTls(CFG.host);
  assertEquals(sawReject, false);
});

// ---------------------------------------------------------------------------
// F1: a connect that resolves AFTER the deadline is still closed (no fd leak)
// ---------------------------------------------------------------------------

Deno.test("connect timeout closes a socket that resolves after the deadline (no fd leak)", async () => {
  const late = new FakeByteConn(new Uint8Array(0));
  let resolveConn!: (c: ByteConn) => void;
  const connecting = new Promise<ByteConn>((res) => {
    resolveConn = res;
  });
  const deps: TransportDeps = {
    connect: () => connecting,
    startTls: (_c, _h, _r) => Promise.resolve(late),
  };
  const t = defaultTransportFactory({ ...CFG, timeoutMs: 1 }, deps);
  // The deadline (1 ms) fires while deps.connect is still pending.
  await assertRejects(() => t.connect(), Error, "connect timed out");
  // The socket now arrives late, AFTER the connect already rejected. The
  // connect-timeout path must still close it -- the factory never captured it
  // into `conn`, so the method's finally->close() has nothing to close and the
  // fd would otherwise leak.
  resolveConn(late);
  await new Promise((r) => setTimeout(r, 5));
  assertEquals(late.closed, true);
});

// ---------------------------------------------------------------------------
// F2: the deactivate audit record never aliases a script literally named
// "__none__"
// ---------------------------------------------------------------------------

Deno.test("setActive: deactivate audit instance name cannot collide with a script named __none__", async () => {
  // Case 1: deactivate (name ""), with some other script currently active.
  const d = handshakeBytes('"foo" ACTIVE', "OK");
  const td = new FakeTransport(d.pre, d.post);
  const ctxD = makeContext();
  await model.methods.setActive.execute(
    { name: "", dryRun: true, _transport: transportFactory(td) },
    ctxD.context,
  );
  // Case 2: activate a script that is LITERALLY named "__none__".
  const a = handshakeBytes('"__none__"', "OK");
  const ta = new FakeTransport(a.pre, a.post);
  const ctxA = makeContext();
  await model.methods.setActive.execute(
    { name: "__none__", dryRun: true, _transport: transportFactory(ta) },
    ctxA.context,
  );
  assertEquals(ctxD.writes[0].name, "deactivate");
  assertEquals(ctxA.writes[0].name, "activate:__none__");
  // The regression guard: the two audit records must NOT share an instance
  // name (the old "activate:__none__" deactivate sentinel aliased case 2).
  assertEquals(ctxD.writes[0].name !== ctxA.writes[0].name, true);
});

// ---------------------------------------------------------------------------
// MS-5: untrusted server text is sanitized before entering errors/resources
// ---------------------------------------------------------------------------

Deno.test("MS-5: sanitizeServerText strips CR/LF and control bytes, collapses, and caps", () => {
  // A forged log line + a terminal escape.
  const hostile = "line1\r\n[ADMIN] forged\x1b[31m entry";
  const clean = sanitizeServerText(hostile);
  assertEquals(/[\r\n]/.test(clean), false);
  // deno-lint-ignore no-control-regex -- asserting no control bytes remain.
  assertEquals(/[\u0000-\u001F\u007F-\u009F]/.test(clean), false);
  assertEquals(clean, "line1 [ADMIN] forged [31m entry");
  // Length cap.
  const long = "x".repeat(500);
  assertEquals(sanitizeServerText(long, 50).length, 53); // 50 + "..."
});

Deno.test("MS-5: describeTerm sanitizes server code/text used in thrown errors", () => {
  const term: TerminalResponse = {
    tag: "NO",
    code: "TRYLATER",
    text: "fail\r\nInjected: evil",
  };
  const desc = describeTerm(term);
  assertEquals(/[\r\n]/.test(desc), false);
  assertEquals(desc, "NO (TRYLATER) fail Injected: evil");
});

Deno.test("MS-5: a NO with newline-laced text reaches the caller as a single sanitized error line", async () => {
  // The server frames its CRLF-laced human text as a literal (the only way a
  // single logical response line can contain CRLF). describeTerm must
  // collapse it so no forged log line reaches the thrown error.
  const t = new FakeTransport(
    wireLines("NO " + serverLiteral("denied\r\nX-Forged-Log: 1")),
  );
  await assertRejects(
    () => cmdSetActive(t, "s"),
    Error,
    "denied X-Forged-Log: 1",
  );
});

Deno.test("MS-5: serverResponse persisted by a write method carries sanitized text", async () => {
  // PUTSCRIPT returns OK with a control-laced human message; it must be
  // sanitized before being written into the `applied` resource.
  const { pre, post } = handshakeBytes(
    "OK", // LISTSCRIPTS (empty)
    "OK", // CHECKSCRIPT ok
    "OK " + serverLiteral("stored\r\nok-note"), // PUTSCRIPT OK, injected newline
  );
  const t = new FakeTransport(pre, post);
  const { context, writes } = makeContext();
  await model.methods.putScript.execute(
    {
      name: "n",
      text: "stop;",
      dryRun: false,
      _transport: transportFactory(t),
    },
    context,
  );
  const sr = writes[0].data.serverResponse as { text: string };
  assertEquals(/[\r\n]/.test(sr.text), false);
  assertEquals(sr.text, "stored ok-note");
});

// ---------------------------------------------------------------------------
// MS-1: a read failure inside a method closes the transport and rethrows
// ---------------------------------------------------------------------------

Deno.test("MS-1: a method closes the transport and rethrows when a read fails (e.g. timeout)", async () => {
  // FakeTransport whose first readLine rejects (stand-in for a timeout).
  class FailingReadTransport extends FakeTransport {
    override readLine(): Promise<string> {
      return Promise.reject(new Error("ManageSieve socket read timed out"));
    }
  }
  const t = new FailingReadTransport(new Uint8Array(0));
  await assertRejects(
    () =>
      model.methods.listScripts.execute(
        { _transport: transportFactory(t) },
        makeContext().context,
      ),
    Error,
    "timed out",
  );
  // cleanup() in the method's finally must have closed the transport.
  assertEquals(t.closed, true);
});
