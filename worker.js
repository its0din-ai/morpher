/**
 * Morpher - Cloudflare Worker (classic service-worker format)
 *
 * 1. Acts as a forwarding proxy for any target URL
 *    (target from ?url=, X-Target-URL header, or /<path> style).
 * 2. Forwards the real connecting IP (the peer "in front of" this proxy,
 *    i.e. CF-Connecting-IP) to the target/origin as the X-Morph-Real-Ip header.
 * 3. Logs visits to an OUT-OF-BAND listener: when a proxied request is heading
 *    to one of the configured target domains (plain domains or wildcards like
 *    *.example.com), a log entry is buffered and POSTed in batches to the
 *    listener URL. No KV required.
 *
 * Classic-format Workers expose bindings as globals, so this script uses
 * OOB_URL / OOB_AUTH / OOB_TOKEN / OOB_DOMAINS directly (injected at deploy
 * time from `python3 morpher.py oob ...`):
 *   OOB_URL      - listener endpoint; unset => logging disabled
 *   OOB_AUTH     - "bearer" or "none" (how to authenticate to the listener)
 *   OOB_TOKEN    - optional bearer token for the listener
 *   OOB_DOMAINS  - comma-separated target allowlist; entries may be plain
 *                  hosts (match apex + all subdomains) or wildcards like
 *                  "*.example.com" (match subdomains only, never the apex).
 *
 * Tune the batching knobs in CONFIG below, then redeploy:
 *   python3 morpher.py update
 */

addEventListener('fetch', (event) => {
  event.respondWith(handleProxy(event));
});

const CONFIG = {
  // Real client IP forwarded to the origin.
  realIpHeader: 'X-Morph-Real-Ip',
  // When true, an inbound X-Morph-Real-Ip header (from an upstream Morpher hop)
  // is honored so a chain of proxies exposes the outermost real IP. Only enable
  // this if every hop is YOUR Morpher worker -- otherwise any direct client can
  // forge the header. When false (default) we always use CF-Connecting-IP, which
  // is the authoritative IP of whoever actually connected to this worker.
  trustChainedRealIp: false,
  // Header a client can set to control the (masked) IP the origin sees via X-Forwarded-For.
  maskedXffInputHeader: 'X-My-X-Forwarded-For',
  maskedXffHeader: 'X-Forwarded-For',

  // Out-of-band logging.
  // Max buffered log entries before we POST a batch to the listener.
  oobBatchSize: 100,
  // POST a batch at least this often (ms), even if the batch is not full.
  oobFlushEveryMs: 30000,
  // Hard cap on buffered entries while the listener is unreachable
  // (oldest entries are dropped first).
  oobMaxBuffered: 2000,
};

/* Per-isolate log buffer (isolates are long-lived under traffic). */
let pendingLogs = [];
let flushTimer = null;
let flushing = false;
let lastFlushTs = 0;

/* ------------------------------------------------------------------ *
 * Binding accessors (classic workers expose bindings as globals)
 * ------------------------------------------------------------------ */

function oobUrl() {
  return typeof OOB_URL !== 'undefined' ? OOB_URL : '';
}

function oobAuth() {
  return typeof OOB_AUTH !== 'undefined' ? OOB_AUTH : 'bearer';
}

function oobToken() {
  return typeof OOB_TOKEN !== 'undefined' ? OOB_TOKEN : '';
}

function oobDomains() {
  return typeof OOB_DOMAINS !== 'undefined' ? OOB_DOMAINS : '';
}

/* ------------------------------------------------------------------ *
 * Proxy
 * ------------------------------------------------------------------ */

async function handleProxy(event) {
  const request = event.request;
  const record = {
    ts: Date.now(),
    method: request.method,
    ip: resolveRealIp(request),
    target: undefined,
    host: undefined,
    xff: undefined,
    status: undefined,
    via: new URL(request.url).hostname,
    ua: (request.headers.get('user-agent') || '').slice(0, 200) || undefined,
    err: undefined,
    logged: false,
    oobMatched: false,
  };

  try {
    const url = new URL(request.url);
    const targetUrl = getTargetUrl(url, request.headers);

    if (!targetUrl) {
      return createErrorResponse(
        'No target URL specified',
        {
          usage: {
            query_param: '?url=https://example.com',
            header: 'X-Target-URL: https://example.com',
            path: '/https://example.com',
          },
        },
        400
      );
    }

    let targetURL;
    try {
      targetURL = new URL(targetUrl);
    } catch (e) {
      return createErrorResponse('Invalid target URL', { provided: targetUrl }, 400);
    }

    // Forward query params but drop our own control params.
    const targetParams = new URLSearchParams();
    for (const [key, value] of url.searchParams) {
      if (!['url', '_cb', '_t'].includes(key)) {
        targetParams.append(key, value);
      }
    }
    if (targetParams.toString()) {
      targetURL.search = targetParams.toString();
    }

    record.target = targetURL.toString();
    record.host = targetURL.hostname.toLowerCase();

    const maskedXff = request.headers.get(CONFIG.maskedXffInputHeader) || generateRandomIP();
    record.xff = maskedXff;

    const proxyRequest = createProxyRequest(request, targetURL, record.ip, maskedXff);

    let response = null;
    let error = null;
    try {
      response = await fetch(proxyRequest);
      record.status = response.status;
    } catch (e) {
      error = e && e.message ? e.message : String(e);
      record.status = 0;
      record.err = error;
    }

    logVisit(event, record);

    if (response) {
      return createProxyResponse(response, request.method, record);
    }

    return createErrorResponse(
      'Proxy request failed',
      { message: error, timestamp: new Date().toISOString() },
      502,
      record
    );
  } catch (error) {
    // Internal/unexpected error. Log it too if we already know the target host.
    record.status = record.status === undefined ? 500 : record.status;
    record.err = record.err || (error && error.message ? error.message : String(error));
    logVisit(event, record);
    return createErrorResponse(
      'Proxy request failed',
      {
        message: error && error.message ? error.message : String(error),
        timestamp: new Date().toISOString(),
      },
      500
    );
  }
}

function getTargetUrl(url, headers) {
  // Priority: query param > header > path
  let targetUrl = url.searchParams.get('url');
  if (!targetUrl) {
    targetUrl = headers.get('X-Target-URL');
  }
  if (!targetUrl && url.pathname !== '/') {
    const pathUrl = url.pathname.slice(1);
    if (pathUrl.startsWith('http')) {
      targetUrl = pathUrl;
    }
  }
  return targetUrl;
}

/**
 * The IP of whoever is in front of this proxy:
 *  1. CF-Connecting-IP (what Cloudflare actually saw connect to this worker) --
 *     authoritative, cannot be forged by the client.
 *  2. If CONFIG.trustChainedRealIp is on, an inbound X-Morph-Real-Ip (set by an
 *     upstream Morpher hop) takes precedence so chains expose the outermost IP.
 *  3. First value of a client supplied X-Forwarded-For, as a last resort.
 */
function resolveRealIp(request) {
  if (CONFIG.trustChainedRealIp) {
    const chained = request.headers.get(CONFIG.realIpHeader);
    if (chained) {
      return chained.split(',')[0].trim();
    }
  }
  const cf = request.headers.get('CF-Connecting-IP');
  if (cf) {
    return cf.trim();
  }
  const xff = request.headers.get('X-Forwarded-For');
  if (xff) {
    return xff.split(',')[0].trim();
  }
  return '';
}

function createProxyRequest(request, targetURL, realIp, maskedXff) {
  const proxyHeaders = new Headers();
  const allowedHeaders = [
    'accept',
    'accept-language',
    'accept-encoding',
    'authorization',
    'cache-control',
    'content-type',
    'origin',
    'referer',
    'user-agent',
  ];

  for (const [key, value] of request.headers) {
    if (allowedHeaders.includes(key.toLowerCase())) {
      proxyHeaders.set(key, value);
    }
  }

  proxyHeaders.set('Host', targetURL.host);
  proxyHeaders.set(CONFIG.maskedXffHeader, maskedXff);
  if (realIp) {
    proxyHeaders.set(CONFIG.realIpHeader, realIp);
  }

  return new Request(targetURL.toString(), {
    method: request.method,
    headers: proxyHeaders,
    body: ['GET', 'HEAD'].includes(request.method) ? null : request.body,
    redirect: 'manual',
  });
}

function createProxyResponse(response, requestMethod, record) {
  const responseHeaders = new Headers();

  for (const [key, value] of response.headers) {
    if (
      !['content-encoding', 'content-length', 'transfer-encoding'].includes(key.toLowerCase())
    ) {
      responseHeaders.set(key, value);
    }
  }

  responseHeaders.set('Access-Control-Allow-Origin', '*');
  responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD');
  responseHeaders.set('Access-Control-Allow-Headers', '*');

  const oob = oobHeaderValue(record);
  if (oob) {
    responseHeaders.set('X-Morpher-Oob', oob);
  }

  if (requestMethod === 'OPTIONS') {
    return new Response(null, { status: 204, headers: responseHeaders });
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders,
  });
}

function generateRandomIP() {
  return [1, 2, 3, 4].map(() => Math.floor(Math.random() * 255) + 1).join('.');
}

/* ------------------------------------------------------------------ *
 * Out-of-band logging (batched)
 * ------------------------------------------------------------------ */

function logVisit(event, record) {
  if (record.logged) {
    return;
  }
  record.logged = true;

  // Only forward visits to configured target domains.
  if (!oobUrl() || !record.host || !hostAllowed(record.host, oobDomains())) {
    return;
  }

  record.oobMatched = true;
  enqueue(event, record);
}

function enqueue(event, entry) {
  pendingLogs.push(entry);

  // Never buffer unboundedly while the listener is down.
  trimBuffer();

  const now = Date.now();
  // Flush when the batch is full, when a flush is due on the interval, OR when
  // this is the first entry seen by this isolate (lastFlushTs === 0). The last
  // case guarantees delivery even for isolated/sparse requests: a single visit
  // on a fresh isolate must not sit in a buffer that may never be flushed.
  const dueNow =
    pendingLogs.length >= CONFIG.oobBatchSize ||
    lastFlushTs === 0 ||
    now - lastFlushTs >= CONFIG.oobFlushEveryMs;

  if (dueNow) {
    if (flushTimer) {
      clearTimeout(flushTimer);
      flushTimer = null;
    }
    event.waitUntil(flush());
    return;
  }

  if (!flushTimer) {
    flushTimer = setTimeout(() => {
      flushTimer = null;
      flush().catch(() => {});
    }, CONFIG.oobFlushEveryMs);
  }
}

function trimBuffer() {
  if (pendingLogs.length > CONFIG.oobMaxBuffered) {
    pendingLogs.splice(0, pendingLogs.length - CONFIG.oobMaxBuffered);
  }
}

/**
 * Allowlist matching:
 *  - plain host  "example.com"   matches the apex AND any subdomain.
 *  - wildcard    "*.example.com" matches any (depth) subdomain, never the apex.
 * An empty/undefined allowlist means "forward logs for every target".
 */
function hostAllowed(host, domainsBinding) {
  if (!domainsBinding) {
    return true;
  }
  const domains = domainsBinding
    .split(',')
    .map((d) => d.trim().toLowerCase().replace(/\.+$/, ''))
    .filter(Boolean);
  if (!domains.length) {
    return true;
  }

  const cleanHost = host.toLowerCase().replace(/\.+$/, '');
  for (const pattern of domains) {
    if (matchHost(cleanHost, pattern)) {
      return true;
    }
  }
  return false;
}

function matchHost(host, pattern) {
  if (pattern.includes('*')) {
    // Standard glob: * may span dots/labels, but the literal suffix still has
    // to be present, so "*.example.com" requires a leading label and never
    // matches the bare apex "example.com".
    const re = new RegExp('^' + escapeRegExp(pattern).replace(/\\\*/g, '.*') + '$');
    return re.test(host);
  }
  // Plain domain: apex or any subdomain.
  return host === pattern || host.endsWith('.' + pattern);
}

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function flush() {
  if (flushing || pendingLogs.length === 0 || !oobUrl()) {
    return;
  }
  flushing = true;
  const batch = pendingLogs;
  pendingLogs = [];
  lastFlushTs = Date.now();

  const requeue = () => {
    pendingLogs = batch.concat(pendingLogs);
    trimBuffer();
  };

  try {
    const headers = { 'content-type': 'application/json' };
    if (oobAuth() !== 'none' && oobToken()) {
      headers['authorization'] = 'Bearer ' + oobToken();
    }

    const resp = await fetch(oobUrl(), {
      method: 'POST',
      headers: headers,
      body: JSON.stringify(batch),
    });

    if (!resp.ok) {
      if (resp.status >= 500) {
        // Transient server error on the listener - retry later.
        requeue();
      } else {
        // 4xx = client error (bad URL, bad auth...). Retrying won't help,
        // so drop the batch instead of spinning forever.
        console.error('Morpher OOB dropped batch:', resp.status);
      }
    }
  } catch (e) {
    // Listener unreachable - retry later.
    requeue();
  } finally {
    flushing = false;
  }
}

/* ------------------------------------------------------------------ *
 * Helpers
 * ------------------------------------------------------------------ */

/**
 * Debug aid returned as the X-Morpher-Oob response header so you can confirm
 * whether a given proxied request was forwarded to the OOB listener:
 *   "1"   - logged (target host matched the allowlist, batch queued)
 *   "0"   - OOB is configured but the target host is NOT in the allowlist
 *   "off" - OOB logging is not configured (no listener URL / no target host)
 */
function oobHeaderValue(record) {
  if (!record) {
    return undefined;
  }
  if (record.oobMatched) {
    return '1';
  }
  if (oobUrl() && record.host) {
    return '0';
  }
  return 'off';
}

function createErrorResponse(error, details, status, record) {
  const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD',
    'Access-Control-Allow-Headers': '*',
  };
  const oob = oobHeaderValue(record);
  if (oob) {
    headers['X-Morpher-Oob'] = oob;
  }
  return new Response(JSON.stringify({ error: error, ...details }), {
    status,
    headers,
  });
}
