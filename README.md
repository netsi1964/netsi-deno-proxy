# netsi-deno-proxy

En gennemsigtig HTTP-proxy til **nye Deno Deploy** (`console.deno.com`). Ingen
dependencies, ingen build, én fil.

```
GET /proxy?url=<url-encoded>&method=POST
```

## Kontrakt

|                 |                                                                                                    |
| --------------- | -------------------------------------------------------------------------------------------------- |
| `url`           | Påkrævet. Absolut `http`- eller `https`-URL, url-encoded.                                          |
| `method`        | Valgfri. `GET` som default. Tilladt: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS.                 |
| Request-body    | Videresendes streamet for alt undtagen GET/HEAD.                                                   |
| Request-headere | Videresendes, undtagen `host`, `content-length`, `origin`, `referer`, `sec-fetch-*` og hop-by-hop. |
| Svar            | Original status, statustekst, headere og body.                                                     |
| Redirects       | Følges ikke. En 302 returneres som en 302 med sin `Location`.                                      |
| `/`             | Dokumentationsside med indbygget tester.                                                           |
| `/health`       | `{"status":"ok","version":"…"}`                                                                    |

## Bevidste afvigelser fra et 1:1-svar

Fire ting kan ikke spejles ordret uden at ødelægge svaret:

1. `Access-Control-Allow-Origin: *` og `Access-Control-Expose-Headers: *` tilføjes. Uden
   dem kasserer browseren svaret, og så er proxyen formålsløs.
2. `X-netsi-deno-proxy: netsi-deno-proxy/1.0.0` tilføjes.
3. Hop-by-hop-headere fjernes. De beskriver en forbindelse der ikke længere findes.
4. `content-encoding` og `content-length` fjernes: `fetch` har allerede pakket body ud, så
   de oprindelige værdier ville beskrive bytes klienten aldrig modtager.

Målets egne `access-control-*`-headere fjernes også, så et target ikke kan overskrive
proxyens CORS-holdning.

## Grænser

| Indstilling            | Env                   | Default  |
| ---------------------- | --------------------- | -------- |
| Requests/minut pr. IP  | `RATE_PER_MINUTE`     | 60       |
| Burst                  | `RATE_BURST`          | 10       |
| Upstream-timeout       | `UPSTREAM_TIMEOUT_MS` | 30000    |
| Maks. svarstørrelse    | `MAX_BODY_BYTES`      | 10485760 |
| Maks. IP'er i tælleren | `MAX_TRACKED_CLIENTS` | 20000    |

Blokerede mål: privat, loopback, link-local, CGNAT, multicast og cloud-metadata
(`169.254.169.254`), både IPv4 og IPv6.

## Kør lokalt

```bash
deno task dev          # http://localhost:8000
deno task check        # typecheck + lint + fmt
```

## Deploy

Nye Deploy — ikke Classic, den lukkede 20. juli 2026.

```bash
deno deploy
```

Eller kobl repoet til en app på `console.deno.com`; builds kører integreret, ingen GitHub
Actions-YAML. Env-variable sættes pr. kontekst (production/development). Custom domæne:
tilføj `_acme-challenge` CNAME først, regn med op til 48 timers DNS-propagering før den
gamle `netsi-deno-proxy.deno.dev` kan pensioneres.

## Tech debt

Begge er tagget i koden med `// TODO: TECH DEBT`.

1. **Rate limit lever i hukommelsen pr. isolate.** Deploy kører flere isolates i to
   regioner, så det reelle loft er ca. `RATE_PER_MINUTE × antal live isolates`, og
   tælleren nulstilles ved cold start. Det bremser løbske scripts — det stopper ikke en
   distribueret flood. Skal loftet være præcist: flyt tælleren til Deno KV med atomare
   counters. Skal den holde til et angreb: sæt Cloudflare foran.
2. **SSRF-værnet tjekker hostname, ikke opslaget.** Et domæne der resolver til en privat
   adresse (DNS rebinding) slipper igennem. Ligegyldigt så længe proxyen ikke deler
   netværk med noget privat — kritisk hvis den nogensinde gør.

## Logning

Kun to ting logges, begge som JSON på stderr og synlige i Deploys Observability-fane:
`blocked_target` (nogen forsøgte en spærret adresse) og `upstream_failed` (målet svarede
ikke). Almindelige kald logges ikke — Deploy tæller dem selv, og en proxy der logger hver
request begraver de få fejl der faktisk betyder noget.
