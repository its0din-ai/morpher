# Morpher 🔀

**Cloudflare Workers forwarding proxies with out-of-band visit logging.**

Morpher is an evolution of FlareProx. It deploys Cloudflare Workers that forward traffic for any target URL, and adds two things on top:

1. **Out-of-band (OOB) visit logging** — when a proxied request is heading to one of your configured target domains, a log entry is batched up and POSTed to *your own* listener (webhook). You watch the visits wherever your listener points.
2. **`X-Morph-Real-Ip` header** — the real IP in front of the proxy is forwarded to the target/origin in a custom header.

Everything runs on Cloudflare's serverless platform, there is nothing to host, and **no KV / database is used** — logs go straight to your listener. All HTTP methods are supported and the Cloudflare free tier applies (100k requests/day).

## Features

- **OOB visit logging, batched:**
  - logs requests whose **target host matches the allowlist** — plain domains match
    the apex and all subdomains (`example.com` also matches `www.example.com`),
    and **wildcards** like `*.example.com` match subdomains only (never the apex)
  - every attempt is logged, including **failures** (origin down, 5xx) for matching domains
  - log entries are buffered in the Worker and POSTed as a **JSON array** to your listener URL when the batch fills up (`oobBatchSize`, default 100) or every `oobFlushEveryMs` (default 30s)
  - each entry: `ts`, `ip` (real connecting IP), `xff` (the masked IP the origin saw), `method`, `target`, `host`, `status`, `via` (the endpoint), `ua`
  - **auth modes**: `bearer` (optional `Authorization: Bearer <token>`) or `none` (bare POST, for open listeners)
  - while the listener is down, batches are requeued and retried (bounded by `oobMaxBuffered`, default 2000)
- **`X-Morph-Real-Ip` forwarding** to the target URI. By default the value is `CF-Connecting-IP` — the authoritative IP of whoever actually connected to this Worker — so it cannot be spoofed by a direct client. Resolution order:
  1. `CF-Connecting-IP` (the peer Cloudflare actually saw connect)
  2. a chained `X-Morph-Real-Ip` header, **only** if you enable `CONFIG.trustChainedRealIp: true` in `worker.js` (for your own Morpher-hop chains — see below)
  3. otherwise the first `X-Forwarded-For` value
- All the original proxy behavior: query param / `X-Target-URL` header / path routing, all HTTP methods, CORS, configurable masked `X-Forwarded-For` via `X-My-X-Forwarded-For`.

## How OOB logging works

```
visitor ──> your Morpher Worker ──> target (receives X-Morph-Real-Ip)
                 │  (if target host is in the allowlist)
                 ▼
        in-isolate buffer (batch size / interval)
                 ▼
        POST [ {ts, ip, xff, method, target, host, status, via, ua}, ... ]
                 ▼
        your OOB listener (webhook)  ← you read the visits here
```

- The listener URL, auth mode (`bearer`/`none`), optional bearer token and the domain allowlist (with wildcards) are **injected as Worker bindings** from the local, git-ignored `morpher_state.json`. No secrets live in `worker.js` or in git.
- Batching keeps your listener (and the Worker's CPU) from getting one request per visit. Tune `oobBatchSize`, `oobFlushEveryMs`, `oobMaxBuffered` in `CONFIG` at the top of `worker.js`, then redeploy with `python3 morpher.py update`.

## Quick Start

### 1. Install

```bash
cd morpher
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure Cloudflare Access

```bash
python3 morpher.py config
```

or edit `morpher.json` directly:

```json
{
  "cloudflare": {
    "api_token": "your_cloudflare_api_token",
    "account_id": "your_cloudflare_account_id"
  }
}
```

Your API token only needs **`Workers Scripts` → Edit** (no KV permission required). The *"Edit Cloudflare Workers"* template works as-is.

### 2b. Example configuration files

Ready-made, commented-free templates ship in the repo: `morpher.example.json` and
`morpher_state.example.json` (copy them to `morpher.json` / `morpher_state.json`, or
use the `config` / `oob` commands which create them for you).

`morpher.json` — Cloudflare credentials (git-ignored):

```json
{
  "cloudflare": {
    "api_token": "your_cloudflare_api_token",
    "account_id": "your_cloudflare_account_id",
    "zone_id": "optional"
  }
}
```

`morpher_state.json` — out-of-band logging config. This file is **managed by the CLI**
(`python3 morpher.py oob ...`), but you may edit it by hand and then run
`python3 morpher.py update`:

```json
{
  "oob": {
    "url": "https://listener.example.com/hook",
    "auth": "bearer",
    "token": "your-listener-secret",
    "domains": ["example.com", "*.api.example.com"]
  }
}
```

| Field | Meaning |
| --- | --- |
| `oob.url` | Where batched visit logs are POSTed (JSON arrays). Empty/missing ⇒ logging disabled. |
| `oob.auth` | `"bearer"` (send `Authorization: Bearer <token>`) or `"none"` (bare POST, no auth header). Default `"bearer"`. |
| `oob.token` | Optional listener token, used only when `auth` is `"bearer"`. |
| `oob.domains` | Target allowlist; logs only traffic heading to these hosts. `example.com` matches the apex + all subdomains; `*.example.com` matches subdomains only (never the apex). Empty ⇒ log every proxied target. |

Worker-side batching knobs live in `CONFIG` at the top of `worker.js`
(`oobBatchSize`, `oobFlushEveryMs`, `oobMaxBuffered`).

### 3. Deploy endpoints

```bash
# Create 2 endpoints (auto-named)
python3 morpher.py create --count 2

# Create one endpoint with a custom worker name (the 'morpher-' prefix is added
# automatically if you omit it)
python3 morpher.py create --name myproxy

# See your endpoints
python3 morpher.py list
```

### 4. Point visits at your OOB listener

```bash
# Only log traffic destined for example.com (and its subdomains), using a token
python3 morpher.py oob \
  --url https://listener.example.com/hook \
  --token your-listener-secret \
  --domains example.com,*.api.example.com

# Same, but your listener needs NO authentication (bare POST, no header)
python3 morpher.py oob --url https://listener.example.com/hook --auth none

# Switch an existing config to auth:none without deleting the stored token
python3 morpher.py oob --auth none

# Log every proxied target (no domain filter)
python3 morpher.py oob --url https://listener.example.com/hook

# Show / disable the config
python3 morpher.py oob
python3 morpher.py oob --clear
```

`oob` saves the config locally **and** redeploys your endpoints. If no endpoints exist yet, just run `create` afterwards.

Your listener receives batched JSON arrays like:

```json
[
  {
    "ts": 1710000000000,
    "method": "GET",
    "ip": "203.0.113.7",
    "xff": "91.5.1.2",
    "target": "https://example.com/login",
    "host": "example.com",
    "status": 200,
    "via": "morpher-1715...-abc123.youraccount.workers.dev",
    "ua": "curl/8.4"
  }
]
```

### 5. Use your proxies

```bash
# Forward a request (query param form)
curl "https://morpher-....workers.dev?url=https://httpbin.org/headers"

# Custom header form
curl -H "X-Target-URL: https://httpbin.org/headers" https://morpher-....workers.dev

# POST through the proxy
curl -X POST -d '{"hi":"there"}' -H "Content-Type: application/json" \
  "https://morpher-....workers.dev?url=https://httpbin.org/post"
```

**Real IP forwarding in action** — the origin sees the visitor's real IP:

```bash
curl -s "https://morpher-....workers.dev?url=https://httpbin.org/headers" \
  | python3 -m json.tool
# -> "X-Morph-Real-Ip": "<real IP of whoever connected to the proxy>"
# -> "X-Forwarded-For": "<random masked IP>"   (what origins normally see)
```

**Chaining** — to keep exposing the *outermost* real IP through a chain of Morpher hops, set `trustChainedRealIp: true` in `worker.js` and redeploy (`python3 morpher.py update`). Only do this when every hop is your own Worker; with the flag off, a direct client could otherwise just forge the header:

```bash
curl -s "https://morpher-A....workers.dev?url=https://morpher-B....workers.dev/?url=https://httpbin.org/headers"
```

**Controlling the masked IP** the origin sees via `X-Forwarded-For` (legacy FlareProx behavior):

```bash
curl -H "X-My-X-Forwarded-For: 1.2.3.4" \
  "https://morpher-....workers.dev?url=https://httpbin.org/headers"
```

> Note: `X-Morph-Real-Ip` is always the *real* connecting IP as seen by Cloudflare — the `X-My-X-Forwarded-For` spoofing only changes the `X-Forwarded-For` header, not the real-IP header.

### Verify everything end-to-end

```bash
# Shows, per endpoint, the X-Morph-Real-Ip the origin received
python3 morpher.py test
```

## Operations

| Command | What it does |
| --- | --- |
| `python3 morpher.py config` | set up / update Cloudflare credentials |
| `python3 morpher.py create --count N` | deploy N auto-named endpoints |
| `python3 morpher.py create --name myproxy` | deploy one endpoint with a custom name |
| `python3 morpher.py list` | list endpoints |
| `python3 morpher.py oob --url ... [--auth none\|bearer] [--token ...] [--domains ...]` | configure OOB logging + redeploy |
| `python3 morpher.py oob` | show current OOB config |
| `python3 morpher.py oob --clear` | disable OOB logging |
| `python3 morpher.py test [--url ...]` | test endpoints (shows forwarded real IP) |
| `python3 morpher.py update` | re-deploy `worker.js` to existing endpoints (after tuning CONFIG) |
| `python3 morpher.py rename --endpoint OLD --name NEW` | rename an endpoint (deploys new worker, then deletes the old) |
| `python3 morpher.py cleanup` | delete all endpoints |
| `python3 morpher.py cleanup --purge` | delete endpoints **and** local state files |

Everything sensitive lives in two git-ignored local files:
- `morpher.json` — Cloudflare credentials
- `morpher_state.json` — OOB listener URL + token + domain allowlist

## Log retry & failure notes

- If the listener is unreachable or answers **5xx**, the batch is requeued for the next flush attempt. Buffered logs are bounded by `oobMaxBuffered` (oldest dropped first) so a dead listener can't blow up Worker memory.
- A **4xx** response (bad URL, bad token…) means retrying won't help, so the batch is **dropped** instead of being retried forever — check your `oob` config.
- A batch that was partially received before an error can be re-sent, so build idempotency into your listener if duplicates matter.
- Workers isolates can be evicted after ~30s idle; a small tail of buffered logs may be lost at the very end of a quiet period (≤ `oobFlushEveryMs` worth).
- Failed proxied requests (origin down / 5xx) for matching domains are logged too, with `status: 0` / `err` set.
- The **first** buffered entry on any Worker is flushed immediately, so isolated/sparse requests (e.g. a single `curl` test) are delivered instead of waiting on the interval timer. Continuous traffic then batches normally.

## Troubleshooting

- **"My domain match isn't logging"** — check the `X-Morpher-Oob` response header on any
  proxied request:
  - `1` = forwarded to the listener (host matched the allowlist),
  - `0` = OOB is configured but the target host is **not** in the allowlist,
  - `off` = no listener URL configured on the Worker.
- **Changing `morpher_state.json` by hand doesn't take effect** — OOB config is baked into
  the deployed Workers as bindings. After editing, run `python3 morpher.py update` (or use
  the `oob` command, which redeploys automatically).
- **"Cloudflare rejected uploading worker … (HTTP …)"** — the real status code and
  Cloudflare error (`[code] message`) are now shown. If it's `401/403`, the token or
  account is the problem: the token needs **`Workers Scripts` → Edit** permission and
  `account_id` must belong to the account the token was created for. Recreate the token
  with the *"Edit Cloudflare Workers"* template if in doubt.
- Morpher deploys a **classic (service-worker format)** script, so no `export default`
  appears in `worker.js`. The OOB bindings (`OOB_URL`, `OOB_AUTH`, `OOB_TOKEN`,
  `OOB_DOMAINS`) are configured **inline in the upload metadata** — this is why your
  Worker needs **no KV permission** and why redeploys (`update`) apply config changes
  atomically.
- A `400` upload response usually points at the Worker script itself; check for a syntax
  error in `worker.js` (paste it into `wrangler deploy` or a JS linter to confirm).

## Disclaimer

Morpher is provided for legitimate development, testing, and research. You are responsible for complying with all applicable laws and the terms of service of any services you access through it, and for how you handle the personal data (IPs, user agents) that your listener records.
