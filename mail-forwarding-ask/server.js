/**
 * server.js — Caddy on_demand_tls ask endpoint (MariaDB-backed allowlist, cached)
 *
 * Goal: avoid hammering MariaDB on every TLS handshake.
 * Strategy:
 *  - In-memory Set cache of allowed domains from:
 *      1) dns_requests.target
 *      2) domain.name
 *  - SOFT TTL: serve cache immediately; refresh in background (singleflight).
 *  - HARD TTL: if too old, MUST refresh; if refresh fails -> fail-closed (403).
 *  - EXTRA REDUNDANCY: hard-coded exact allowlist + hard-coded suffix/base allowlist.
 *
 * Env:
 *  - ASK_HOST=127.0.0.1
 *  - ASK_PORT=9000
 *
 *  - DB_HOST=127.0.0.1
 *  - DB_PORT=3306
 *  - DB_USER=mailuser
 *  - DB_PASS=...
 *  - DB_NAME=maildb
 *  - DB_CONN_LIMIT=10
 *
 *  - ASK_DB_TYPE=UI
 *  * ASK_DB_STATUS=ACTIVE
 *
 *  - ASK_CACHE_SOFT_TTL_MS=10000
 *  - ASK_CACHE_HARD_TTL_MS=60000
 *  - ASK_CACHE_MIN_WARMUP_MS=0   (optional; delay initial refresh)
 *
 *  - ASK_INVALIDATE_TOKEN=...    (optional; enables POST /cache/invalidate)
 */

"use strict";

const express = require("express");
const mariadb = require("mariadb");
const crypto = require("node:crypto");

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "32kb" }));

// ---- config ----
const HOST = process.env.ASK_HOST || "127.0.0.1";
const PORT = Number(process.env.ASK_PORT || 9000);

const DB_HOST = process.env.DB_HOST || "127.0.0.1";
const DB_PORT = Number(process.env.DB_PORT || 3306);
const DB_USER = process.env.DB_USER || "root";
const DB_PASS = process.env.DB_PASS || "";
const DB_NAME = process.env.DB_NAME || "maildb";
const DB_CONN_LIMIT = Number(process.env.DB_CONN_LIMIT || 10);

const DB_TYPE = (process.env.ASK_DB_TYPE || "UI").toUpperCase();
const DB_STATUS = (process.env.ASK_DB_STATUS || "ACTIVE").toUpperCase();

const CACHE_SOFT_TTL_MS = Number(process.env.ASK_CACHE_SOFT_TTL_MS || 10_000);
const CACHE_HARD_TTL_MS = Number(process.env.ASK_CACHE_HARD_TTL_MS || 60_000);
const CACHE_MIN_WARMUP_MS = Number(process.env.ASK_CACHE_MIN_WARMUP_MS || 0);

const INVALIDATE_TOKEN = process.env.ASK_INVALIDATE_TOKEN || "";

// ---- hard-coded redundancy allowlist ----
// Exact-match allowlist.
// These domains return 200 even if DB/cache path is unavailable.
const HARD_CODED_ALLOWLIST = new Set([
  "mail.thc.org",
  // "dark-mail.thc.org",
]);

// Base/suffix allowlist.
// Return 200 if the requested domain is EXACTLY one of these,
// or ANY subdomain under them, regardless of depth.
const HARD_CODED_SUFFIX_ALLOWLIST = new Set([
  "503.lat",
  "abin.lat",
  "balestrastore.com",
  "ciphine.com",
  "cobaltstrike.org",
  "email-shield.org",
  "extencil.me",
  "hackerschoice.org",
  "haltman.io",
  "haltman.org",
  "homoglyph.org",
  "johntheripper.org",
  "kerberoast.org",
  "lockbit.io",
  "metasploit.io",
  "meu.bingo",
  "mishandle.org",
  "polkit.org",
  "pwnd.lat",
  "revil.org",
  "stealth.rest",
  "unhandle.org",
]);

// ---- mariadb pool ----
const pool = mariadb.createPool({
  host: DB_HOST,
  port: DB_PORT,
  user: DB_USER,
  password: DB_PASS,
  database: DB_NAME,
  connectionLimit: DB_CONN_LIMIT,
  // Important: we want stability more than fancy behavior.
  // mariadb driver will handle reconnect per query; keep it simple.
});

// ---- helpers ----
function normalizeHost(h) {
  if (!h) return "";
  h = String(h).trim().toLowerCase();
  // Remove trailing dot (FQDN form)
  if (h.endsWith(".")) h = h.slice(0, -1);
  return h;
}

/**
 * Conservative hostname validation:
 * - allow: a-z 0-9 . -
 * - forbid: wildcard, scheme, spaces, path/query
 * - label rules: 1..63 chars, no leading/trailing hyphen
 * - total length: <=253
 */
function isValidHostname(h) {
  if (!h || h.length > 253) return false;
  if (h.includes("*")) return false;
  if (h.includes("://")) return false;
  if (/[\/\s?#:@]/.test(h)) return false; // path/query/userinfo-ish

  // basic charset
  if (!/^[a-z0-9.-]+$/.test(h)) return false;

  const parts = h.split(".");
  if (parts.some((p) => p.length === 0)) return false; // no empty labels
  for (const label of parts) {
    if (label.length < 1 || label.length > 63) return false;
    if (label.startsWith("-") || label.endsWith("-")) return false;
  }
  return true;
}

function isHardCodedAllowed(domain) {
  return HARD_CODED_ALLOWLIST.has(domain);
}

function isSubdomainOrSame(domain, base) {
  return domain === base || domain.endsWith(`.${base}`);
}

function isHardCodedSuffixAllowed(domain) {
  for (const base of HARD_CODED_SUFFIX_ALLOWLIST) {
    if (isSubdomainOrSame(domain, base)) return true;
  }
  return false;
}

async function dbQuery(sql, params) {
  let conn;
  try {
    conn = await pool.getConnection();
    return await conn.query(sql, params);
  } finally {
    if (conn) conn.release();
  }
}

// ---- allowlist cache (Set) ----
const allowCache = {
  set: new Set(),
  loadedAt: 0,          // last successful refresh (ms)
  lastAttemptAt: 0,     // last refresh attempt (ms)
  refreshing: null,     // Promise or null (singleflight)
  lastError: null,
};

async function refreshAllowlist() {
  // singleflight
  if (allowCache.refreshing) return allowCache.refreshing;

  allowCache.lastAttemptAt = Date.now();

  allowCache.refreshing = (async () => {
    const sqlDnsRequests = `
      SELECT target
      FROM dns_requests
      WHERE type = ?
        AND status = ?
        AND expires_at > NOW()
    `;

    const sqlDomains = `
      SELECT name
      FROM domain
    `;

    const [dnsRows, domainRows] = await Promise.all([
      dbQuery(sqlDnsRequests, [DB_TYPE, DB_STATUS]),
      dbQuery(sqlDomains, []),
    ]);

    const next = new Set();

    // dns_requests.target
    for (const r of Array.isArray(dnsRows) ? dnsRows : []) {
      if (!r || typeof r !== "object") continue;
      const host = normalizeHost(r.target);
      if (host && isValidHostname(host)) next.add(host);
    }

    // domain.name
    for (const r of Array.isArray(domainRows) ? domainRows : []) {
      if (!r || typeof r !== "object") continue;
      const host = normalizeHost(r.name);
      if (host && isValidHostname(host)) next.add(host);
    }

    allowCache.set = next;
    allowCache.loadedAt = Date.now();
    allowCache.lastError = null;

    return allowCache.set;
  })()
    .catch((err) => {
      allowCache.lastError = err;
      throw err;
    })
    .finally(() => {
      allowCache.refreshing = null;
    });

  return allowCache.refreshing;
}

function cacheAgeMs() {
  return allowCache.loadedAt ? Date.now() - allowCache.loadedAt : Number.POSITIVE_INFINITY;
}

function shouldSoftRefresh() {
  return cacheAgeMs() > CACHE_SOFT_TTL_MS;
}

function isHardExpired() {
  return cacheAgeMs() > CACHE_HARD_TTL_MS;
}

/**
 * Returns current allowlist Set.
 * - If cache is fresh -> return immediately
 * - If soft expired -> return cached Set AND kick refresh in background
 * - If hard expired -> await refresh; if fails -> propagate error (fail-closed upstream)
 */
async function getAllowlistSet() {
  // Warmup path: if never loaded, treat as hard expired.
  if (!allowCache.loadedAt) {
    await refreshAllowlist();
    return allowCache.set;
  }

  if (isHardExpired()) {
    // must refresh
    await refreshAllowlist();
    return allowCache.set;
  }

  if (shouldSoftRefresh()) {
    // serve cached and refresh in background
    refreshAllowlist().catch(() => {});
  }

  return allowCache.set;
}

// ---- endpoints ----

/**
 * Caddy on_demand_tls ask endpoint.
 * Caddy calls with ?domain=example.com
 *
 * Behavior:
 * - Invalid/empty domain -> 403
 * - Allowed by hard-coded exact array -> 200
 * - Allowed by hard-coded suffix/base array -> 200
 * - Allowed by DB/cache exact match -> 200
 * - Not allowed -> 403
 * - Cache hard-expired and refresh fails -> 403 (fail-closed),
 *   except for hard-coded domains which are still allowed.
 */
app.get("/ask", async (req, res) => {
  const raw = req.query && req.query.domain;
  const domain = normalizeHost(raw);

  if (!isValidHostname(domain)) {
    return res.status(403).send("forbidden\n");
  }

  if (isHardCodedAllowed(domain)) {
    console.log(`[ask] allowed (hardcoded exact): ${domain}`);
    return res.status(200).send("ok\n");
  }

  if (isHardCodedSuffixAllowed(domain)) {
    console.log(`[ask] allowed (hardcoded suffix): ${domain}`);
    return res.status(200).send("ok\n");
  }

  try {
    const set = await getAllowlistSet();
    if (set.has(domain)) {
      console.log(`[ask] allowed (db exact): ${domain}`);
      return res.status(200).send("ok\n");
    }
    return res.status(403).send("forbidden\n");
  } catch (e) {
    // fail-closed: do not allow unknown state to mint certs
    return res.status(403).send("forbidden\n");
  }
});

// ---- cache management ----
app.get("/healthz", (_req, res) => {
  return res.status(200).json({
    ok: true,
    uptime_sec: Math.floor(process.uptime()),
    cache: {
      entries: allowCache.set.size,
      loaded_at: allowCache.loadedAt || null,
      age_ms: Number.isFinite(cacheAgeMs()) ? cacheAgeMs() : null,
      soft_ttl_ms: CACHE_SOFT_TTL_MS,
      hard_ttl_ms: CACHE_HARD_TTL_MS,
      last_attempt_at: allowCache.lastAttemptAt || null,
      refreshing: Boolean(allowCache.refreshing),
      last_error: allowCache.lastError ? String(allowCache.lastError.message || allowCache.lastError) : null,
    },
    db: {
      host: DB_HOST,
      port: DB_PORT,
      name: DB_NAME,
      type_filter: DB_TYPE,
      status_filter: DB_STATUS,
      connection_limit: DB_CONN_LIMIT,
    },
    redundancy: {
      hardcoded_exact_entries: HARD_CODED_ALLOWLIST.size,
      hardcoded_suffix_entries: HARD_CODED_SUFFIX_ALLOWLIST.size,
    },
    now: Date.now(),
  });
});

app.post("/cache/invalidate", async (req, res) => {
  const token = req.get("x-invalidate-token") || req.body?.token || "";
  if (!INVALIDATE_TOKEN || !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(INVALIDATE_TOKEN))) {
    return res.status(403).json({ ok: false, error: "forbidden" });
  }

  allowCache.loadedAt = 0;

  try {
    await refreshAllowlist();
    return res.status(200).json({
      ok: true,
      entries: allowCache.set.size,
      loaded_at: allowCache.loadedAt,
    });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      error: String(err.message || err),
    });
  }
});

// ---- startup ----
setTimeout(() => {
  refreshAllowlist().catch((err) => {
    console.error("[warmup] allowlist refresh failed:", err && err.message ? err.message : err);
  });
}, CACHE_MIN_WARMUP_MS);

app.listen(PORT, HOST, () => {
  console.log(`[boot] ask server listening on http://${HOST}:${PORT}`);
  console.log(`[boot] db=${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME} type=${DB_TYPE} status=${DB_STATUS}`);
  console.log(`[boot] cache soft=${CACHE_SOFT_TTL_MS}ms hard=${CACHE_HARD_TTL_MS}ms`);
});
