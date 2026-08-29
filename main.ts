/**
 * netsi-deno-proxy — a transparent HTTP proxy for Deno Deploy.
 *
 * GET /proxy?url=<encoded>&method=POST
 *
 * The upstream response is mirrored as closely as a browser-facing proxy can:
 * same status, same status text, same headers, same body — except for the
 * documented deviations listed in DEVIATIONS below.
 */

const VERSION = "1.0.0";
const PROXY_HEADER = "X-netsi-deno-proxy";
const PROXY_VALUE = `netsi-deno-proxy/${VERSION}`;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const num = (name: string, fallback: number) => {
  const raw = Deno.env.get(name);
  const parsed = raw === undefined ? NaN : Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};

const CONFIG = {
  /** Sustained requests per minute, per client IP, per isolate. */
  ratePerMinute: num("RATE_PER_MINUTE", 60),
  /** How many requests may be spent in one go before the sustained rate bites. */
  rateBurst: num("RATE_BURST", 10),
  /** Upstream timeout. */
  timeoutMs: num("UPSTREAM_TIMEOUT_MS", 30_000),
  /** Hard ceiling on the proxied response body. */
  maxBodyBytes: num("MAX_BODY_BYTES", 10 * 1024 * 1024),
  /** Safety valve on the rate-limit table so one isolate can't be memory-bombed. */
  maxTrackedClients: num("MAX_TRACKED_CLIENTS", 20_000),
};

const METHODS = [
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
];

const BODYLESS_METHODS = new Set(["GET", "HEAD"]);

/**
 * Hop-by-hop headers are connection-scoped. Forwarding them corrupts the
 * response — they describe the previous hop, not the payload.
 */
const HOP_BY_HOP = new Set([
  "connection",
  "proxy-connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

/**
 * Deviations from a byte-identical passthrough. Every one of these is a
 * deliberate choice, not an oversight; the index page lists them for users.
 */
const DEVIATIONS = [
  "Access-Control-Allow-Origin: * is added, otherwise a browser cannot read the response at all.",
  "Access-Control-Expose-Headers: * is added, otherwise browser JS sees only a handful of the original headers.",
  `${PROXY_HEADER} is added, identifying the proxy.`,
  "Hop-by-hop headers (connection, transfer-encoding, keep-alive, ...) are dropped — they describe a connection that no longer exists.",
  "content-encoding and content-length are dropped: fetch has already decompressed the body, so the original values would describe bytes the client never receives.",
  "Redirects are not followed. A 302 is returned as a 302 with its original Location header.",
];

// ---------------------------------------------------------------------------
// Rate limiting — token bucket, in memory, per isolate
// ---------------------------------------------------------------------------

// TODO: TECH DEBT - rate limit state is per-isolate and lost on cold start - replace
// with Deno KV (atomic counters) if the effective ceiling needs to be exact.
// Deno Deploy runs several isolates across regions, so the real ceiling is
// roughly RATE_PER_MINUTE × (number of live isolates). This is a misuse damper,
// not DDoS protection — a distributed flood needs a CDN/WAF in front.

interface Bucket {
  tokens: number;
  updated: number;
}

const buckets = new Map<string, Bucket>();
const refillPerMs = CONFIG.ratePerMinute / 60_000;
let lastSweep = 0;

/** Drop buckets that have been full (i.e. idle) long enough to be uninteresting. */
function sweep(now: number) {
  if (now - lastSweep < 60_000 && buckets.size < CONFIG.maxTrackedClients) return;
  lastSweep = now;
  const fullAfterMs = CONFIG.rateBurst / refillPerMs;
  for (const [key, bucket] of buckets) {
    if (now - bucket.updated > fullAfterMs) buckets.delete(key);
  }
  // Still oversized after the sweep: the table itself is the attack. Reset it.
  if (buckets.size >= CONFIG.maxTrackedClients) buckets.clear();
}

function takeToken(clientId: string): { allowed: boolean; retryAfter: number } {
  const now = Date.now();
  sweep(now);

  const bucket = buckets.get(clientId) ??
    { tokens: CONFIG.rateBurst, updated: now };

  bucket.tokens = Math.min(
    CONFIG.rateBurst,
    bucket.tokens + (now - bucket.updated) * refillPerMs,
  );
  bucket.updated = now;

  if (bucket.tokens < 1) {
    buckets.set(clientId, bucket);
    return {
      allowed: false,
      retryAfter: Math.ceil((1 - bucket.tokens) / refillPerMs / 1000),
    };
  }

  bucket.tokens -= 1;
  buckets.set(clientId, bucket);
  return { allowed: true, retryAfter: 0 };
}

function clientIdOf(request: Request, info: Deno.ServeHandlerInfo): string {
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) return forwarded.split(",")[0].trim();
  const addr = info.remoteAddr;
  return addr.transport === "tcp" ? addr.hostname : "unknown";
}

// ---------------------------------------------------------------------------
// SSRF guard
// ---------------------------------------------------------------------------

// TODO: TECH DEBT - hostname is checked, DNS is not resolved - a name that resolves
// to a private address (DNS rebinding) still passes. Resolve and re-check the
// address before connecting if this proxy ever shares a network with anything private.

const BLOCKED_NAMES = new Set([
  "localhost",
  "metadata.google.internal",
  "metadata",
]);

function isPrivateIPv4(host: string): boolean {
  const parts = host.split(".");
  if (parts.length !== 4) return false;
  const octets = parts.map(Number);
  if (octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) return false;
  const [a, b] = octets;
  return (
    a === 0 || // "this network"
    a === 10 || // private
    a === 127 || // loopback
    (a === 100 && b >= 64 && b <= 127) || // CGNAT
    (a === 169 && b === 254) || // link-local + cloud metadata
    (a === 172 && b >= 16 && b <= 31) || // private
    (a === 192 && b === 168) || // private
    (a === 192 && b === 0) || // IETF protocol assignments
    (a === 198 && (b === 18 || b === 19)) || // benchmarking
    a >= 224 // multicast + reserved + broadcast
  );
}

function isBlockedHost(rawHost: string): boolean {
  const host = rawHost.toLowerCase().replace(/^\[|\]$/g, "");
  if (!host) return true;
  if (BLOCKED_NAMES.has(host)) return true;
  if (host.endsWith(".localhost") || host.endsWith(".local")) return true;

  if (host.includes(":")) {
    // IPv6
    if (host === "::1" || host === "::") return true;
    if (/^f[cd]/.test(host)) return true; // unique local
    if (/^fe[89ab]/.test(host)) return true; // link-local
    const mapped = host.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateIPv4(mapped[1]);
    return false;
  }

  return isPrivateIPv4(host);
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

function baseHeaders(extra?: HeadersInit): Headers {
  const headers = new Headers(extra);
  headers.set(PROXY_HEADER, PROXY_VALUE);
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Access-Control-Expose-Headers", "*");
  return headers;
}

/** Readable message out, detail stays in the log. */
function errorResponse(status: number, message: string, extra?: HeadersInit) {
  const headers = baseHeaders(extra);
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(
    JSON.stringify({ error: message, proxy: PROXY_VALUE }, null, 2) + "\n",
    { status, headers },
  );
}

/** The critical path is "a valid request reaches its target and comes back". */
function logFailure(event: string, detail: Record<string, unknown>) {
  console.error(JSON.stringify({ event, at: new Date().toISOString(), ...detail }));
}

// ---------------------------------------------------------------------------
// Proxying
// ---------------------------------------------------------------------------

function buildUpstreamHeaders(request: Request): Headers {
  const headers = new Headers();
  // Any header named in Connection is hop-by-hop for this request only.
  const connectionListed = new Set(
    (request.headers.get("connection") ?? "")
      .split(",")
      .map((v) => v.trim().toLowerCase())
      .filter(Boolean),
  );

  for (const [name, value] of request.headers) {
    const key = name.toLowerCase();
    if (HOP_BY_HOP.has(key) || connectionListed.has(key)) continue;
    if (key === "host" || key === "content-length") continue;
    // Browser-injected noise that describes the call to the proxy, not the target.
    if (key === "origin" || key === "referer") continue;
    if (key.startsWith("sec-fetch-") || key === "sec-ch-ua") continue;
    headers.set(name, value);
  }
  return headers;
}

function buildDownstreamHeaders(upstream: Response): Headers {
  const headers = baseHeaders();
  const connectionListed = new Set(
    (upstream.headers.get("connection") ?? "")
      .split(",")
      .map((v) => v.trim().toLowerCase())
      .filter(Boolean),
  );

  for (const [name, value] of upstream.headers) {
    const key = name.toLowerCase();
    if (HOP_BY_HOP.has(key) || connectionListed.has(key)) continue;
    // fetch decompressed the body already; these two would now be lies.
    if (key === "content-encoding" || key === "content-length") continue;
    // Never let the target dictate the proxy's own CORS posture.
    if (key.startsWith("access-control-")) continue;
    if (key === PROXY_HEADER.toLowerCase()) continue;
    headers.append(name, value);
  }
  return headers;
}

/** Cut the stream off at the ceiling rather than buffering the whole body. */
function cappedBody(body: ReadableStream<Uint8Array> | null) {
  if (!body) return null;
  let seen = 0;
  return body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        seen += chunk.byteLength;
        if (seen > CONFIG.maxBodyBytes) {
          controller.error(new Error("response body exceeded the size limit"));
          return;
        }
        controller.enqueue(chunk);
      },
    }),
  );
}

async function proxy(request: Request, url: URL): Promise<Response> {
  const target = url.searchParams.get("url");
  if (!target) {
    return errorResponse(400, "Missing 'url' query parameter.");
  }

  let parsed: URL;
  try {
    parsed = new URL(target);
  } catch {
    return errorResponse(400, "The 'url' parameter is not a valid absolute URL.");
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return errorResponse(400, "Only http and https targets are allowed.");
  }

  if (isBlockedHost(parsed.hostname)) {
    logFailure("blocked_target", { host: parsed.hostname });
    return errorResponse(403, "That target address is not reachable through this proxy.");
  }

  const method = (url.searchParams.get("method") ?? "GET").toUpperCase();
  if (!METHODS.includes(method)) {
    return errorResponse(
      400,
      `Unsupported method. Use one of: ${METHODS.join(", ")}.`,
    );
  }

  const hasBody = !BODYLESS_METHODS.has(method) && request.body !== null;

  try {
    const upstream = await fetch(parsed, {
      method,
      headers: buildUpstreamHeaders(request),
      body: hasBody ? request.body : undefined,
      redirect: "manual",
      signal: AbortSignal.timeout(CONFIG.timeoutMs),
      ...(hasBody ? { duplex: "half" } : {}),
    } as RequestInit);

    return new Response(
      method === "HEAD" ? null : cappedBody(upstream.body),
      {
        status: upstream.status,
        statusText: upstream.statusText,
        headers: buildDownstreamHeaders(upstream),
      },
    );
  } catch (error) {
    const timedOut = error instanceof DOMException && error.name === "TimeoutError";
    logFailure("upstream_failed", {
      host: parsed.hostname,
      method,
      reason: error instanceof Error ? error.message : String(error),
    });
    return timedOut
      ? errorResponse(504, "The target did not respond in time.")
      : errorResponse(502, "The target could not be reached.");
  }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

Deno.serve((request, info) => {
  const url = new URL(request.url);

  if (url.pathname === "/health") {
    return new Response(
      JSON.stringify({ status: "ok", version: VERSION }),
      { headers: baseHeaders({ "Content-Type": "application/json" }) },
    );
  }

  const wantsProxy = url.searchParams.has("url") ||
    url.pathname === "/proxy";

  if (!wantsProxy) {
    if (url.pathname !== "/") {
      return errorResponse(404, "Not found. Use /proxy?url=… or open / for the docs.");
    }
    return new Response(indexPage(), {
      headers: baseHeaders({ "Content-Type": "text/html; charset=utf-8" }),
    });
  }

  // Preflight is answered by the proxy itself — the target never sees it.
  if (request.method === "OPTIONS") {
    const requested = request.headers.get("access-control-request-headers");
    return new Response(null, {
      status: 204,
      headers: baseHeaders({
        "Access-Control-Allow-Methods": METHODS.join(", "),
        "Access-Control-Allow-Headers": requested ?? "*",
        "Access-Control-Max-Age": "86400",
      }),
    });
  }

  const clientId = clientIdOf(request, info);
  const { allowed, retryAfter } = takeToken(clientId);
  if (!allowed) {
    return errorResponse(429, "Rate limit reached. Slow down and try again.", {
      "Retry-After": String(Math.max(1, retryAfter)),
      "X-RateLimit-Limit": String(CONFIG.ratePerMinute),
    });
  }

  return proxy(request, url);
});

// ---------------------------------------------------------------------------
// Index page
// ---------------------------------------------------------------------------

function indexPage(): string {
  const deviations = DEVIATIONS.map((d) => `<li>${d}</li>`).join("");
  return `<!doctype html>
<html lang="en" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>netsi-deno-proxy</title>
<style>
  :root {
    --paper: #f4f5f2;
    --card: #ffffff;
    --ink: #14181a;
    --muted: #5c6663;
    --line: #d9ddd6;
    --signal: #0b6e5e;
    --flag: #6b3fa0;
    --warn: #a35400;
    --radius: 4px;
  }
  [data-theme="dark"] {
    --paper: #101413;
    --card: #171c1b;
    --ink: #e9ece9;
    --muted: #939d99;
    --line: #2b3231;
    --signal: #4fc9ae;
    --flag: #b394e0;
    --warn: #e0a765;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    padding: 2.5rem 1.25rem 5rem;
    background: var(--paper);
    color: var(--ink);
    font-family: Avenir, Montserrat, Corbel, 'URW Gothic', source-sans-pro, sans-serif;
    font-weight: normal;
    line-height: 1.6;
    transition: background .2s ease, color .2s ease;
  }
  main { max-width: 52rem; margin: 0 auto; }
  h1 { font-size: 2rem; letter-spacing: -.02em; margin: 0 0 .25rem; }
  h2 { font-size: 1rem; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); margin: 3rem 0 1rem; font-weight: normal; }
  p { color: var(--muted); max-width: 42rem; }
  code, pre, .mono { font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: .85rem; }
  code { background: var(--card); border: 1px solid var(--line); border-radius: var(--radius); padding: .1rem .35rem; color: var(--ink); }
  pre { background: var(--card); border: 1px solid var(--line); border-radius: var(--radius); padding: .9rem 1rem; overflow-x: auto; margin: 0; }
  a { color: var(--signal); }

  header { display: flex; align-items: flex-start; justify-content: space-between; gap: 1rem; }
  .tag { display: inline-block; font-size: .75rem; letter-spacing: .1em; text-transform: uppercase; color: var(--signal); }
  button.theme {
    background: none; border: 1px solid var(--line); color: var(--muted);
    border-radius: var(--radius); padding: .4rem .7rem; cursor: pointer; font: inherit; font-size: .8rem;
  }
  button.theme:hover { color: var(--ink); border-color: var(--muted); }

  /* the lane: what happens to a request on its way through */
  .lane { border-left: 2px solid var(--line); margin: 1.5rem 0 0; padding: 0 0 0 1.5rem; list-style: none; }
  .lane li { position: relative; padding: .55rem 0; }
  .lane li::before {
    content: ''; position: absolute; left: calc(-1.5rem - 5px); top: 1.1rem;
    width: 8px; height: 8px; border-radius: 50%; background: var(--line);
  }
  .lane li[data-kind="pass"]::before { background: var(--signal); }
  .lane li[data-kind="add"]::before { background: var(--flag); }
  .lane li[data-kind="drop"]::before { background: var(--warn); }
  .lane .what { color: var(--ink); }
  .lane .why { display: block; font-size: .85rem; color: var(--muted); }

  form { display: grid; grid-template-columns: 7rem 1fr auto; gap: .6rem; align-items: stretch; margin-top: 1rem; }
  select, input, button.run {
    font: inherit; padding: .6rem .7rem; border: 1px solid var(--line);
    border-radius: var(--radius); background: var(--card); color: var(--ink);
  }
  input:focus-visible, select:focus-visible, button:focus-visible { outline: 2px solid var(--signal); outline-offset: 1px; }
  button.run { background: var(--signal); border-color: var(--signal); color: #fff; cursor: pointer; padding-inline: 1.2rem; }
  button.run:disabled { opacity: .5; cursor: progress; }
  @media (max-width: 34rem) { form { grid-template-columns: 1fr; } }

  .result { margin-top: 1rem; display: none; }
  .result[data-open="true"] { display: block; }
  .status { font-size: .85rem; color: var(--muted); margin-bottom: .6rem; }
  .status b { color: var(--ink); font-weight: normal; }
  .added { color: var(--flag); }
  ul.plain { padding-left: 1.2rem; color: var(--muted); }
  footer { margin-top: 4rem; font-size: .85rem; color: var(--muted); border-top: 1px solid var(--line); padding-top: 1rem; }
  @media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
</style>
</head>
<body>
<main>
  <header>
    <div>
      <span class="tag">${PROXY_VALUE}</span>
      <h1>A proxy that stays out of the way</h1>
    </div>
    <button class="theme" type="button" id="theme">Dark</button>
  </header>

  <p>Give it a URL and it makes the request for you, then hands back the answer with
  the original status and the original headers. Useful when a browser refuses a call
  because the target sends no CORS headers of its own.</p>

  <pre>GET /proxy?url=https://example.com/api&amp;method=POST</pre>

  <h2>What happens to your request</h2>
  <ul class="lane">
    <li data-kind="pass"><span class="what">Your headers and body travel on untouched</span>
      <span class="why">Authorization, content-type, cookies — all forwarded as sent.</span></li>
    <li data-kind="drop"><span class="what">Origin, Referer and Sec-Fetch-* are removed</span>
      <span class="why">They describe your call to the proxy, not the call to the target.</span></li>
    <li data-kind="pass"><span class="what">The target's status and headers come back verbatim</span>
      <span class="why">A 404 is a 404. A redirect is returned, not followed.</span></li>
    <li data-kind="add"><span class="what">${PROXY_HEADER} is added to the response</span>
      <span class="why">So you can always tell a proxied response from a direct one.</span></li>
    <li data-kind="add"><span class="what">CORS headers are added</span>
      <span class="why">Without them your browser would discard the response before you saw it.</span></li>
  </ul>

  <h2>Try it</h2>
  <form id="tester">
    <select id="method" aria-label="Method">
      ${
    METHODS.map((m) => `<option${m === "GET" ? " selected" : ""}>${m}</option>`).join("")
  }
    </select>
    <input id="target" type="url" value="https://api.github.com/repos/denoland/deno" aria-label="Target URL" placeholder="https://…">
    <button class="run" type="submit">Send</button>
  </form>
  <div class="result" id="result">
    <div class="status" id="status"></div>
    <pre id="headers"></pre>
    <pre id="body" style="margin-top:.6rem"></pre>
  </div>

  <h2>Limits</h2>
  <ul class="plain">
    <li>${CONFIG.ratePerMinute} requests per minute per IP, with up to ${CONFIG.rateBurst} in one burst. Over that you get a <code>429</code> and a <code>Retry-After</code>.</li>
    <li>Counted in each server instance's own memory, so the real ceiling is a little higher than the number above. It stops runaway scripts; it is not protection against a distributed flood.</li>
    <li>Responses stop at ${
    (CONFIG.maxBodyBytes / 1024 / 1024).toFixed(0)
  } MB and targets get ${(CONFIG.timeoutMs / 1000).toFixed(0)} seconds to answer.</li>
    <li>Private and link-local addresses are refused, including cloud metadata endpoints.</li>
  </ul>

  <h2>Where it differs from a direct call</h2>
  <ul class="plain">${deviations}</ul>

  <footer>netsi-deno-proxy ${VERSION} · <a href="/health">/health</a> · built by Netsi</footer>
</main>

<script>
  var root = document.documentElement;
  var toggle = document.getElementById('theme');
  var stored = localStorage.getItem('netsi-deno-proxy-theme');
  if (stored) root.dataset.theme = stored;
  else if (matchMedia('(prefers-color-scheme: dark)').matches) root.dataset.theme = 'dark';
  function label() { toggle.textContent = root.dataset.theme === 'dark' ? 'Light' : 'Dark'; }
  label();
  toggle.addEventListener('click', function () {
    root.dataset.theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
    localStorage.setItem('netsi-deno-proxy-theme', root.dataset.theme);
    label();
  });

  var form = document.getElementById('tester');
  var out = document.getElementById('result');
  var statusEl = document.getElementById('status');
  var headersEl = document.getElementById('headers');
  var bodyEl = document.getElementById('body');
  var button = form.querySelector('button');

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    var target = document.getElementById('target').value.trim();
    if (!target) return;
    var method = document.getElementById('method').value;
    var url = '/proxy?url=' + encodeURIComponent(target) + '&method=' + method;

    button.disabled = true;
    out.dataset.open = 'true';
    statusEl.textContent = 'Sending…';
    headersEl.textContent = '';
    bodyEl.textContent = '';
    var started = performance.now();

    fetch(url).then(function (response) {
      var ms = Math.round(performance.now() - started);
      statusEl.innerHTML = '<b>' + response.status + ' ' + (response.statusText || '') + '</b> · ' + ms + ' ms';
      var lines = [];
      response.headers.forEach(function (value, name) {
        var added = name.toLowerCase().indexOf('x-netsi-deno-proxy') === 0 ||
                    name.toLowerCase().indexOf('access-control-') === 0;
        lines.push((added ? '+ ' : '  ') + name + ': ' + value);
      });
      lines.sort();
      headersEl.textContent = lines.join('\\n');
      return response.text();
    }).then(function (text) {
      bodyEl.textContent = text.length > 4000 ? text.slice(0, 4000) + '\\n…' : text;
    }).catch(function (error) {
      statusEl.textContent = 'The request could not be completed: ' + error.message;
    }).finally(function () {
      button.disabled = false;
    });
  });
</script>
</body>
</html>`;
}
