# netsi-deno-proxy — full API reference

> A public, keyless HTTP/CORS proxy. You give it a URL, it fetches that URL and
> mirrors the response back with permissive CORS headers so browser JavaScript can
> read it. Use it when a target API has no CORS headers of its own.

Base URL: https://netsi-proxy-deno.netsi1964.deno.net
No authentication. No API key. No sign-up.

## The one call you need

```
GET /proxy?url=<url-encoded target>&method=<HTTP method>
```

```bash
curl "https://netsi-proxy-deno.netsi1964.deno.net/proxy?url=https%3A%2F%2Fexample.com"
```

```js
const target = "https://api.example.com/items?page=2&limit=10";
const res = await fetch(
  "https://netsi-proxy-deno.netsi1964.deno.net/proxy?url=" + encodeURIComponent(target),
);
```

## Parameters

| Param    | Required | Notes                                                                                     |
| -------- | -------- | ----------------------------------------------------------------------------------------- |
| `url`    | yes      | Absolute `http:` or `https:` URL, URL-encoded.                                              |
| `method` | no       | Method used against the target. Default `GET`. One of GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS. |

MOST COMMON MISTAKE: not URL-encoding `url`. If the target contains `&`, `?`, `=`
or `#` and you paste it raw, the proxy reads the target's query string as its own
and fetches the wrong thing. Always use `encodeURIComponent` (JS),
`urllib.parse.quote(url, safe="")` (Python) or `--data-urlencode` (curl).

## Sending a request body

The method against the target is the `method` query parameter, not the method you
use against the proxy. To POST, do both: POST to the proxy AND pass `method=POST`.
The body is streamed through for everything except GET and HEAD.

```bash
curl -X POST -H 'content-type: application/json' -d '{"hello":"world"}' \
  "https://netsi-proxy-deno.netsi1964.deno.net/proxy?url=https%3A%2F%2Fapi.example.com%2Fitems&method=POST"
```

Your request headers are forwarded to the target, so `Authorization`,
`Content-Type` and friends work as expected. Dropped on the way out: `host`,
`content-length`, `origin`, `referer`, `sec-fetch-*`, `sec-ch-ua` and hop-by-hop
headers — they describe your call to the proxy, not the call to the target.

The proxy adds two headers of its own naming the caller:

```
Forwarded: for=<your IP address>
X-Client-IP: <your IP address>
```

The address is read from the network connection, so anything you send under
`forwarded`, `x-forwarded-*`, `x-real-ip` or `x-client-ip` is discarded before the
request goes out — you cannot present yourself to the target as another address.
`X-Forwarded-For` is deliberately not used: Deno's `fetch` strips it from outgoing
requests, so setting it would be a promise the runtime does not keep.

This means the target sees the caller's IP address, not just the proxy's.

Sending credentials through a third-party proxy means the proxy operator can see
them. This one does not log them, but do not send tokens you would not hand over.

## What comes back

The target's status, status text, headers and body, as-is. Five deliberate
deviations, because a byte-identical mirror would be useless in a browser:

1. `Access-Control-Allow-Origin: *` added — without it the browser discards the response.
2. `Access-Control-Expose-Headers: *` added — without it JS sees only a handful of headers.
3. `X-netsi-deno-proxy: netsi-deno-proxy/1.0.0` added.
4. Hop-by-hop headers dropped — they describe a connection that no longer exists.
5. `content-encoding` and `content-length` dropped — fetch already decompressed the
   body, so the original values would describe bytes you never receive.

The target's own `access-control-*` headers are stripped, so a target cannot
override the proxy's CORS posture.

Redirects are NOT followed. A 302 comes back as a 302 with its original `Location`.
If you want the redirect followed, read `Location` and make a second proxy call.

## Errors

Errors come from the proxy as JSON; anything else is the target's own response.

```json
{ "error": "Missing 'url' query parameter.", "proxy": "netsi-deno-proxy/1.0.0" }
```

| Status | Meaning                                                                        |
| ------ | ------------------------------------------------------------------------------ |
| 400    | `url` missing, not an absolute URL, not http/https, or `method` unsupported.    |
| 403    | Target address is blocked (see below).                                          |
| 404    | Unknown path on the proxy itself.                                               |
| 429    | Rate limited. Honour `Retry-After` (seconds).                                   |
| 502    | Target could not be reached.                                                    |
| 504    | Target did not respond within 30s.                                              |

A 502 or 504 is about the target, not about your request being malformed —
retrying the same call verbatim after a pause is reasonable. A 400 or 403 will
never succeed on retry; fix the call instead.

## Limits

| Limit                   | Default          |
| ----------------------- | ---------------- |
| Requests per minute/IP  | 60               |
| Burst                   | 10               |
| Upstream timeout        | 30s              |
| Max response body       | 10 MiB           |

Exceeding the body ceiling aborts the stream mid-response rather than returning a
clean error, so a truncated body on a very large target is expected behaviour.

The rate limit is per isolate and resets on cold start, so the effective ceiling is
higher and not exact. Do not rely on it as a quota — treat 60/min as the contract.

## Blocked targets

Requests to private, loopback, link-local, CGNAT, multicast and cloud-metadata
addresses are refused with 403, IPv4 and IPv6 alike — including `169.254.169.254`,
`localhost`, `*.localhost`, `*.local` and `metadata.google.internal`. This is an
SSRF guard. It is not a bug and there is no bypass.

## Other endpoints

| Path       | Returns                                                                  |
| ---------- | ------------------------------------------------------------------------ |
| `/health`  | `{"status":"ok","version":"1.0.0"}`                                      |
| `/`        | HTML documentation with a built-in request tester.                       |
| `OPTIONS`  | CORS preflight, answered by the proxy itself with 204. The target never sees it. |

Any path carrying a `url` query parameter proxies, so `/?url=…` behaves like
`/proxy?url=…`. Prefer `/proxy` — it is the canonical form.

## Source

https://github.com/netsi1964/netsi-deno-proxy — single file, no dependencies,
runs on Deno Deploy.
