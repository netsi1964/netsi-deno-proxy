# AGENTS.md

Instructions for AI agents working _on_ this repository.

If you only want to _call_ the deployed proxy, read `llms.txt` instead — it is the usage
contract and it is all you need.

## What this is

A transparent HTTP/CORS proxy for Deno Deploy. One file, zero dependencies, no build step.
`main.ts` is the whole program: config, rate limiter, SSRF guard, proxy logic, server and
the HTML documentation page.

- Live: https://netsi-proxy-deno.netsi1964.deno.net
- Deploy org/app: `netsi1964` / `netsi-proxy-deno` (see `deno.json` → `deploy`)

## Commands

```bash
deno task dev      # watch mode on http://localhost:8000
deno task start    # run once
deno task check    # deno check main.ts && deno lint && deno fmt --check
```

Run `deno task check` before every commit. `deno fmt` reformats Markdown too, at
`lineWidth: 90` — expect it to reflow README.md and this file.

There is no test suite. Verify changes against a running instance with curl, and exercise
at minimum: a normal proxy call, a blocked target, a redirect, an error case, and
`/health`.

## Invariants — do not break these without being asked

- **Zero dependencies and one runtime file.** No imports from jsr/npm, no build step, no
  static asset files. The HTML page is a template string on purpose.
- **The response is a mirror.** Status, status text, headers and body pass through
  untouched except for the five deviations listed in `DEVIATIONS` in `main.ts`. Those five
  are documented in README.md and `llms.txt`; changing the set means changing all three.
- **The target never dictates CORS.** Incoming `access-control-*` headers from the target
  are stripped. Do not "fix" this by forwarding them.
- **Redirects are not followed** (`redirect: "manual"`). This is deliberate.
- **The SSRF guard is not optional.** `isBlockedHost` refuses private, loopback,
  link-local, CGNAT, multicast and metadata addresses. Do not add bypass flags.
- **Logging stays quiet.** Only `blocked_target` and `upstream_failed` are logged, as JSON
  on stderr. Do not add per-request logging — it buries the failures that matter, and
  Deploy already counts requests.

## Deliberate tech debt — do not report these as bugs

Both are tagged `// TODO: TECH DEBT` in `main.ts` and explained in README.md.

1. Rate-limit state is in memory per isolate, so the real ceiling is roughly
   `RATE_PER_MINUTE × live isolates` and resets on cold start. It is a misuse damper, not
   DDoS protection. Fixing it properly means Deno KV atomic counters.
2. The SSRF guard checks the hostname, not the resolved address, so DNS rebinding passes.
   Harmless while the proxy shares no network with anything private.

## Keeping the docs honest

Three files describe the same contract and drift apart easily:

- `README.md` — for humans, in Danish.
- `llms.txt` — for LLMs and agents calling the service, in English.
- `indexPage()` in `main.ts` — the HTML page served at `/`.

Change the behaviour, change all three.

## Deploy

New Deno Deploy (`console.deno.com`). Deploy Classic was sunset on 20 July 2026 — every
`*.deno.dev` URL is dead, and `deployctl` is the wrong tool.

```bash
deno deploy            # interactive; org and app come from deno.json
```

The repo is also connected to the Deploy app, so pushes to `main` build there.

Gotchas that cost the previous session time:

- Authentication lives in the macOS keychain. A sandboxed agent shell cannot reach it and
  `deno deploy` will fail with `NON_INTERACTIVE_REQUIRED`. Either run it in a real
  terminal or pass `DENO_DEPLOY_TOKEN` / `--token`.
- The `deno deploy` wrapper in Deno 2.9.6 injects its own flags: `deno deploy --help` and
  `deno deploy whoami --json` both fail with "Option can only occur once".
- Do NOT run `deno run -A jsr:@deno/deploy` from this directory. It writes the deploy
  CLI's own dependencies (~400 lines of `@cliffy`, `@deno/sandbox`, …) into the project's
  `deno.lock`. This project has no dependencies; that lockfile is noise and is gitignored.

## Conventions

- Comments explain _why_, not _what_. Match the existing density — sparse, and only where
  a reader would otherwise wonder.
- Code and code comments in English. README.md in Danish.
- Bump `VERSION` in `main.ts` and `version` in `deno.json` together; the version is
  visible in `/health` and in the `X-netsi-deno-proxy` header.
