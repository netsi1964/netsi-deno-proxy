---
name: netsi-proxy
description: Fetch a URL through netsi-deno-proxy (https://netsi-proxy-deno.netsi1964.deno.net), a public keyless CORS proxy, and write correct client code against it. Use this skill whenever the user names netsi-proxy, netsi-deno-proxy, netsi-proxy-deno.netsi1964.deno.net, "min proxy", "netsi proxien" or the netsi1964/netsi-deno-proxy repo — whether they want data fetched right now, a fetch/curl/Python snippet written, an error from the proxy explained, or existing proxy calls reviewed. Covers URL-encoding, the `method` parameter, response header rewrites, redirects, error codes and limits. Do not reach for this skill when the user has not named this proxy: a target that already sends CORS headers needs no proxy at all.
---

# netsi-proxy

A public, keyless HTTP/CORS proxy. Give it a URL, it fetches that URL and mirrors
the response back with permissive CORS headers, so browser JavaScript can read a
target that sends no CORS headers of its own.

Base URL: `https://netsi-proxy-deno.netsi1964.deno.net`
No authentication, no API key, no sign-up.

## The one call

```
GET /proxy?url=<url-encoded target>&method=<HTTP method against the target>
```

Everything else in this skill is detail around that line.

## Rule 1: always URL-encode `url`

This is the failure that accounts for most broken proxy calls. If the target has
`&`, `?`, `=` or `#` in it and is pasted raw, the proxy parses the target's query
string as its own and fetches something other than what was intended — usually
without an error, which is what makes it expensive to debug.

Encode it, every time, even when the target looks harmless today:

| Language | Encoder |
| --- | --- |
| JS / TS | `encodeURIComponent(target)` |
| Python | `urllib.parse.quote(target, safe="")` |
| curl | `--data-urlencode "url=$TARGET" -G` |
| Deno / Node | `new URL(...)` + `searchParams.set("url", target)` |

Prefer building the call with `URLSearchParams` when writing code — it encodes for
you and removes the chance of a hand-rolled mistake:

```js
const PROXY = "https://netsi-proxy-deno.netsi1964.deno.net/proxy";

function via(target, method = "GET") {
  const qs = new URLSearchParams({ url: target });
  if (method !== "GET") qs.set("method", method);
  return `${PROXY}?${qs}`;
}

const res = await fetch(via("https://api.example.com/items?page=2&limit=10"));
```

## Rule 2: `method` means the method against the *target*

Two methods are in play and they are not the same one. The method used against the
proxy carries the body; the `method` query parameter is what the proxy uses against
the target. To POST, do both.

```bash
curl -X POST -H 'content-type: application/json' -d '{"hello":"world"}' \
  "https://netsi-proxy-deno.netsi1964.deno.net/proxy?url=https%3A%2F%2Fapi.example.com%2Fitems&method=POST"
```

Allowed values: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS. Default `GET`. The
body is streamed through for everything except GET and HEAD. An unsupported value
gives 400.

## Parameters

| Param | Required | Notes |
| --- | --- | --- |
| `url` | yes | Absolute `http:` or `https:` URL, URL-encoded. |
| `method` | no | Method used against the target. Default `GET`. |

## Headers

Request headers are forwarded to the target, so `Authorization`, `Content-Type`
and friends behave as expected.

Dropped on the way out — they describe the call to the proxy, not the call to the
target: `host`, `content-length`, `origin`, `referer`, `sec-fetch-*`, `sec-ch-ua`
and hop-by-hop headers.

Credentials sent through any third-party proxy are visible to its operator. This
one does not log them, but flag it to the user before writing code that pushes a
token or API key through it, rather than after.

## What comes back

The target's status, status text, headers and body as-is, with five deliberate
deviations — a byte-identical mirror would be useless in a browser:

1. `Access-Control-Allow-Origin: *` added, or the browser discards the response.
2. `Access-Control-Expose-Headers: *` added, or JS sees only a handful of headers.
3. `X-netsi-deno-proxy: netsi-deno-proxy/1.0.0` added.
4. Hop-by-hop headers dropped — they describe a connection that no longer exists.
5. `content-encoding` and `content-length` dropped — fetch already decompressed the
   body, so the original values would describe bytes that never arrive.

The target's own `access-control-*` headers are stripped, so a target cannot
override the proxy's CORS posture.

**Redirects are not followed.** A 302 comes back as a 302 with its original
`Location`. Follow it with a second proxy call:

```js
let res = await fetch(via(target));
if ([301, 302, 303, 307, 308].includes(res.status)) {
  res = await fetch(via(new URL(res.headers.get("location"), target).href));
}
```

## Errors

Proxy errors are JSON; anything else is the target's own response.

```json
{ "error": "Missing 'url' query parameter.", "proxy": "netsi-deno-proxy/1.0.0" }
```

| Status | Meaning | Retry? |
| --- | --- | --- |
| 400 | `url` missing, not absolute, not http/https, or bad `method` | No — fix the call |
| 403 | Target address is blocked (SSRF guard) | No — no bypass exists |
| 404 | Unknown path on the proxy itself | No |
| 429 | Rate limited | Yes, after `Retry-After` seconds |
| 502 | Target unreachable | Yes, verbatim after a pause |
| 504 | Target silent for 30s | Yes, verbatim after a pause |

The distinction that matters when debugging: 502/504 are about the target, so the
same call may well work later. 400/403 are about the call itself and will never
succeed on retry — reading the `error` string beats retrying.

## Limits

| Limit | Default |
| --- | --- |
| Requests per minute per IP | 60 |
| Burst | 10 |
| Upstream timeout | 30s |
| Max response body | 10 MiB |

Exceeding the body ceiling aborts the stream mid-response rather than returning a
clean error, so a truncated body on a very large target is expected. Guard against
it when the target size is unknown: `HEAD` first, or accept the truncation.

The rate limit is per isolate and resets on cold start, so the real ceiling is
higher and inexact. Treat 60/min as the contract and do not build a quota on it.

## Blocked targets

Private, loopback, link-local, CGNAT, multicast and cloud-metadata addresses are
refused with 403, IPv4 and IPv6 alike — including `169.254.169.254`, `localhost`,
`*.localhost`, `*.local` and `metadata.google.internal`. This is the SSRF guard.
It is not a bug and there is no bypass; when a user hits it, say so plainly and
suggest running against a local dev server directly instead.

## Other endpoints

| Path | Returns |
| --- | --- |
| `/health` | `{"status":"ok","version":"1.0.0"}` |
| `/` | HTML docs with a built-in request tester |
| `OPTIONS` | CORS preflight, answered by the proxy itself with 204; the target never sees it |

Any path carrying a `url` parameter proxies, so `/?url=…` works — but write
`/proxy`, it is the canonical form.

## Calling it directly

When the user wants data rather than code, call the proxy from the available
execution tool instead of describing how they could:

```bash
curl -sS -G "https://netsi-proxy-deno.netsi1964.deno.net/proxy" \
  --data-urlencode "url=https://api.example.com/items?page=2"
```

Add `-i` when the interesting part is the status or headers (a redirect, a rate
limit, a content type). Add `-w '\n%{http_code}\n'` when only the code matters.

Before blaming the proxy for a failure, hit `/health` — one call separates "the
proxy is down" from "the target is down", and the answer changes the advice.

## Debugging checklist

Work through this in order when a call misbehaves; the first two catch most cases.

1. Is `url` encoded? Compare the target inside the query string against the
   intended target character by character.
2. For a non-GET target, is `method` set *and* the request to the proxy made with
   a body-carrying method?
3. Is the response JSON with a `proxy` field? Then it is the proxy talking, and
   the table above names the cause. Otherwise the target answered and the status
   is the target's own.
4. Unexpected 3xx and nothing rendered? Redirects are not followed — make the
   second call.
5. Body cut off? Check against the 10 MiB ceiling.
6. `/health` for liveness.

## Full API reference

`references/api.md` holds the complete upstream documentation. Read it when a
question goes past what is above — the exact list of stripped headers, the precise
error strings, or details of the SSRF guard.

Source: https://github.com/netsi1964/netsi-deno-proxy — single file, no
dependencies, runs on Deno Deploy.
