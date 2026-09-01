/**
 * bitwardenClient.js
 * ---------------------------------------------------------------------------
 * HTTPS client for the Bitwarden / Vaultwarden API — just enough of it to
 * store and retrieve SSH key (cipher type 5) items:
 *
 *   POST /identity/accounts/prelogin   -> KDF parameters
 *   POST /identity/connect/token       -> access + refresh token (password grant)
 *   POST /identity/connect/token       -> refresh grant
 *   GET  /api/sync                     -> profile.key, folders, ciphers
 *   POST /api/folders                  -> create the sync folder
 *   POST /api/ciphers                  -> create an item
 *   PUT  /api/ciphers/{id}             -> update an item
 *
 * Server URL safety (SSRF guard, enforced on every client construction):
 *   - http/https schemes only; no embedded credentials; a hostname required
 *   - "localhost", ".localhost" and ".local" names are rejected
 *   - literal IPs in loopback, private, link-local, CGNAT, multicast,
 *     documentation and other reserved ranges are rejected (IPv4 and IPv6,
 *     including IPv4-mapped/6to4 forms)
 *   - the hostname is DNS-resolved and EVERY resolved address must be
 *     public — a name that resolves into a private range is refused
 *
 * Consequence: a self-hosted vault must be reachable via a public hostname
 * (e.g. behind a reverse proxy with a real domain). LAN/localhost addresses
 * are deliberately out of scope for this client.
 * ---------------------------------------------------------------------------
 */

'use strict';

const dns = require('dns').promises;
const bwCrypto = require('./bitwardenCrypto');

const REQUEST_TIMEOUT_MS = 30000;
const CLIENT_ID = 'cli'; // first-party client id accepted by Bitwarden + Vaultwarden
const DEVICE_TYPE = '14'; // SDK

class BitwardenError extends Error {}
class AuthError extends BitwardenError {}

/* ------------------------------------------------------------------------
 * IP range evaluation (SSRF guard)
 * ---------------------------------------------------------------------- */

function v4ToInt(s) {
  const parts = String(s).split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const v = Number(p);
    if (!/^\d+$/.test(p) || v > 255) return null;
    n = n * 256 + v;
  }
  return n;
}

function inCidr4(ip, base, bits) {
  const n = v4ToInt(ip);
  if (n === null) return false;
  const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
  const b = v4ToInt(base);
  return (n & mask) === (b & mask);
}

/** True when an IPv4 address must not be contacted by this client. */
function isRestrictedIPv4(ip) {
  const ranges = [
    ['0.0.0.0', 8],      // "this network"
    ['10.0.0.0', 8],     // private
    ['100.64.0.0', 10],  // CGNAT / shared address space
    ['127.0.0.0', 8],    // loopback
    ['169.254.0.0', 16], // link-local
    ['172.16.0.0', 12],  // private
    ['192.0.0.0', 24],   // IETF protocol assignments
    ['192.0.2.0', 24],   // TEST-NET-1
    ['192.88.99.0', 24], // 6to4 relay anycast (deprecated)
    ['192.168.0.0', 16], // private
    ['198.18.0.0', 15],  // benchmarking
    ['198.51.100.0', 24],// TEST-NET-2
    ['203.0.113.0', 24], // TEST-NET-3
    ['224.0.0.0', 4],    // multicast
    ['240.0.0.0', 4]     // reserved (incl. 255.255.255.255)
  ];
  return ranges.some(([base, bits]) => inCidr4(ip, base, bits));
}

function intToV4(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

/**
 * Expand an IPv6 address into its 8 16-bit groups (numbers), handling the
 * "::" compression and an embedded dotted-quad tail. Returns null if the
 * address is not parseable.
 */
function expandIPv6(addr) {
  let s = String(addr).toLowerCase().replace(/^\[|\]$/g, '');
  if (s === '::') return [0, 0, 0, 0, 0, 0, 0, 0];
  if (s.includes('.')) {
    const m = s.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
    if (!m) return null;
    const n = v4ToInt(m[2]);
    if (n === null) return null;
    s = m[1] + (n >>> 16).toString(16) + ':' + (n & 0xffff).toString(16);
  }
  const dc = s.split('::');
  if (dc.length > 2) return null;
  const head = dc[0] ? dc[0].split(':').filter(Boolean) : [];
  const tail = dc.length === 2 && dc[1] ? dc[1].split(':').filter(Boolean) : [];
  const missing = 8 - head.length - tail.length;
  if (dc.length === 2 && missing < 1) return null;
  if (dc.length === 1 && head.length !== 8) return null;
  const groups = head.slice();
  if (dc.length === 2) for (let i = 0; i < missing; i++) groups.push('0');
  for (const t of tail) groups.push(t);
  if (groups.length !== 8) return null;
  const out = [];
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    out.push(parseInt(g, 16));
  }
  return out;
}

/** Evaluate an IPv6 address; IPv4-embedded forms are checked as IPv4. */
function isRestrictedIPv6(ip) {
  const g = expandIPv6(ip);
  if (!g) return true; // unparseable → refuse by default
  const low32 = ((g[6] << 16) | g[7]) >>> 0;
  if (g.every(v => v === 0)) return true; // unspecified
  // IPv4-mapped ::ffff:0:0/96 and deprecated IPv4-compatible ::/96
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0) {
    if (g[5] === 0xffff) return isRestrictedIPv4(intToV4(low32));
    if (g[5] === 0 && low32 !== 0) return isRestrictedIPv4(intToV4(low32));
  }
  if (g[0] === 0x64 && g[1] === 0xff9b && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0) return true; // NAT64
  if (g[0] === 0x100 && g[1] === 0 && g[2] === 0 && g[3] === 0) return true; // discard-only
  if (g[0] === 0x2001 && (g[1] === 0 || g[1] === 0xdb8)) return true; // Teredo / documentation
  if (g[0] === 0x2002) return true; // 6to4 (deprecated)
  if ((g[0] & 0xfe00) === 0xfc00) return true; // unique-local fc00::/7
  if ((g[0] & 0xffc0) === 0xfe80) return true; // link-local fe80::/10
  if ((g[0] & 0xff00) === 0xff00) return true; // multicast ff00::/8
  return false;
}

/** True when an address (v4 or v6 literal) may not be contacted. */
function isRestrictedAddress(address) {
  return address.includes(':') ? isRestrictedIPv6(address) : isRestrictedIPv4(address);
}

async function defaultDnsLookup(hostname) {
  return dns.lookup(hostname, { all: true, verbatim: true });
}

/**
 * Validate a user-supplied vault server URL and return the normalized base
 * (scheme + host + optional path, no trailing slash). Throws on any unsafe
 * or unusable URL. `lookup` is injectable for tests.
 */
async function resolveSafeServerUrl(serverUrl, lookup = defaultDnsLookup) {
  let url;
  try {
    url = new URL(String(serverUrl).trim());
  } catch (e) {
    throw new BitwardenError('Server URL is not a valid URL.');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new BitwardenError('Server URL must use http:// or https://.');
  }
  if (url.username || url.password) {
    throw new BitwardenError('Server URL must not contain credentials.');
  }
  // hostname comes bracketed for IPv6 literals ([::1]) — strip brackets and
  // any trailing dot (FQDN form) before validation
  const host = url.hostname.toLowerCase().replace(/^\[/, '').replace(/\]$/, '').replace(/\.$/, '');
  if (!host) throw new BitwardenError('Server URL has no hostname.');
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) {
    throw new BitwardenError('Local hostnames are not allowed. Use the public hostname of your vault server.');
  }
  const port = url.port ? Number(url.port) : 0;
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new BitwardenError('Server URL has an invalid port.');
  }
  if (host.includes(':')) {
    // literal IPv6 (URL API already brackets it away from the port)
    if (isRestrictedIPv6(host)) throw new BitwardenError('Reserved or private IP addresses are not allowed.');
  } else if (v4ToInt(host) !== null) {
    if (isRestrictedIPv4(host)) throw new BitwardenError('Reserved or private IP addresses are not allowed.');
  }
  // DNS must resolve, and every resolved address must be public.
  let addrs;
  try {
    addrs = await lookup(host);
  } catch (e) {
    throw new BitwardenError('Cannot resolve server hostname "' + host + '".');
  }
  if (!Array.isArray(addrs) || addrs.length === 0) {
    throw new BitwardenError('Server hostname "' + host + '" does not resolve.');
  }
  for (const a of addrs) {
    if (isRestrictedAddress(a.address)) {
      throw new BitwardenError('"' + host + '" resolves to a private or reserved address (' + a.address + '). ' +
        'Self-hosted vaults must be reachable via a public hostname.');
    }
  }
  const base = url.origin + (url.pathname && url.pathname !== '/' ? url.pathname.replace(/\/+$/, '') : '');
  return base;
}

/* ------------------------------------------------------------------------
 * HTTP client
 * ---------------------------------------------------------------------- */

class BitwardenClient {
  /**
   * @param {{ serverUrl: string, email: string, masterPassword: string,
   *           deviceId: string, fetchImpl?: Function, lookup?: Function }} opts
   */
  constructor(opts) {
    this.serverUrl = String(opts.serverUrl || '').trim();
    this.email = String(opts.email || '').trim();
    this.masterPassword = String(opts.masterPassword || '');
    this.deviceId = opts.deviceId;
    this.fetchImpl = opts.fetchImpl || globalThis.fetch.bind(globalThis);
    this.lookup = opts.lookup;
    this.accessToken = null;
    this.refreshToken = null;
    this.tokenExpiresAt = 0;
    this.masterKey = null;
    this.userKey = null;
  }

  /**
   * Validate URL (incl. DNS), derive the master key and authenticate.
   * Returns the prelogin KDF config used.
   */
  async connect() {
    this.baseUrl = await resolveSafeServerUrl(this.serverUrl, this.lookup);
    if (!this.email.includes('@')) throw new BitwardenError('A valid account email is required.');
    if (!this.masterPassword) throw new AuthError('The vault master password is required.');
    const kdf = await this.prelogin();
    this.masterKey = await bwCrypto.deriveMasterKey(this.masterPassword, this.email, kdf);
    await this._loginWithPassword();
    return kdf;
  }

  async _fetch(url, init) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), REQUEST_TIMEOUT_MS);
    try {
      return await this.fetchImpl(url, { ...init, signal: ctrl.signal });
    } finally {
      clearTimeout(timer);
    }
  }

  async prelogin() {
    const res = await this._fetch(this.baseUrl + '/identity/accounts/prelogin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: this.email })
    });
    if (!res.ok) throw new BitwardenError('Server prelogin failed (HTTP ' + res.status + ').');
    const data = await res.json();
    return {
      kdfType: data.kdf,
      iterations: data.kdfIterations,
      memory: data.kdfMemory,
      parallelism: data.kdfParallelism
    };
  }

  async _tokenRequest(body) {
    const res = await this._fetch(this.baseUrl + '/identity/connect/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(body).toString()
    });
    let data = null;
    try { data = await res.json(); } catch (e) { /* non-JSON error page */ }
    if (!res.ok) {
      if (data && data.TwoFactorProviders) {
        throw new AuthError('This account has two-factor login enabled, which SSHSpan does not support yet. ' +
          'Use a dedicated account without 2FA for the sync.');
      }
      const detail = data && (data.error_description || data.error);
      throw new AuthError('Vault login failed' + (detail ? ': ' + detail : ' (HTTP ' + res.status + ').') +
        ' Check the server URL, account email and master password.');
    }
    this.accessToken = data.access_token;
    this.refreshToken = data.refresh_token || null;
    this.tokenExpiresAt = Date.now() + (Number(data.expires_in) || 3600) * 1000 - 60000;
  }

  async _loginWithPassword() {
    await this._tokenRequest({
      grant_type: 'password',
      username: this.email,
      password: bwCrypto.masterPasswordHash(this.masterKey, this.masterPassword),
      scope: 'api offline_access',
      client_id: CLIENT_ID,
      deviceType: DEVICE_TYPE,
      deviceIdentifier: this.deviceId,
      deviceName: 'SSHSpan'
    });
  }

  async _ensureToken() {
    if (!this.accessToken) throw new AuthError('Not logged in.');
    if (Date.now() < this.tokenExpiresAt) return;
    if (!this.refreshToken) throw new AuthError('Session expired and no refresh token is available.');
    try {
      await this._tokenRequest({
        grant_type: 'refresh_token',
        refresh_token: this.refreshToken,
        client_id: CLIENT_ID
      });
    } catch (e) {
      this.accessToken = null;
      throw new AuthError('Session expired and could not be refreshed. Sync again to re-authenticate.');
    }
  }

  /** Authenticated /api request with one transparent token-refresh retry. */
  async _api(method, path, body) {
    for (let attempt = 0; attempt < 2; attempt++) {
      await this._ensureToken();
      const res = await this._fetch(this.baseUrl + path, {
        method,
        headers: {
          'Authorization': 'Bearer ' + this.accessToken,
          'Content-Type': 'application/json'
        },
        body: body === undefined ? undefined : JSON.stringify(body)
      });
      if (res.status === 401 && attempt === 0) {
        this.tokenExpiresAt = 0; // force refresh path
        continue;
      }
      if (!res.ok) {
        let detail = '';
        try {
          const err = await res.json();
          detail = err && (err.Message || err.message || err.error_description || err.error) || '';
        } catch (e) { /* ignore */ }
        throw new BitwardenError('Vault request ' + method + ' ' + path + ' failed (HTTP ' + res.status + ')' +
          (detail ? ': ' + detail : ''));
      }
      return res.json();
    }
    throw new BitwardenError('Vault request failed after token refresh.');
  }

  /** Full vault sync; decrypts the account user key and folder names. */
  async sync() {
    const data = await this._api('GET', '/api/sync');
    const profile = data.profile || {};
    if (!profile.key) {
      throw new BitwardenError('The account profile has no encryption key (Key Connector accounts are not supported).');
    }
    const stretched = bwCrypto.stretchMasterKey(this.masterKey);
    // The account's user key is encrypted with the stretched master key.
    // New clients store it as RAW bytes; legacy clients stored it
    // base64-encoded text. Accept both.
    const userKeyBytes = await bwCrypto.decryptToBytes(profile.key, stretched);
    if (userKeyBytes.length === 64) {
      this.userKey = userKeyBytes;
    } else if (userKeyBytes.length === 88) {
      this.userKey = Buffer.from(userKeyBytes.toString('utf8'), 'base64');
      if (this.userKey.length !== 64) {
        throw new BitwardenError('Account key decoded to an unexpected length.');
      }
    } else {
      throw new BitwardenError('Unsupported account key format (length ' + userKeyBytes.length + ').');
    }
    const folders = [];
    for (const f of (data.folders || [])) {
      folders.push({
        id: f.id,
        name: await this.decryptField(f.name),
        revisionDate: f.revisionDate
      });
    }
    return {
      folders,
      ciphers: data.ciphers || [],
      profile: { email: profile.email, name: profile.name }
    };
  }

  // Both return Promises (SubtleCrypto is async) — callers MUST await them.
  async encryptField(plaintext) {
    return bwCrypto.encryptString(plaintext, this.userKey);
  }

  async decryptField(encString) {
    return bwCrypto.decryptString(encString, this.userKey);
  }

  async createFolder(name) {
    return this._api('POST', '/api/folders', { name: await this.encryptField(name) });
  }

  async createCipher(cipher) {
    return this._api('POST', '/api/ciphers', cipher);
  }

  async updateCipher(id, cipher) {
    return this._api('PUT', '/api/ciphers/' + encodeURIComponent(id), cipher);
  }

  close() {
    this.accessToken = null;
    this.refreshToken = null;
    this.masterKey = null;
    this.userKey = null;
  }
}

/**
 * Best-effort anonymous server probe used by "Test connection":
 * Vaultwarden exposes /api/config with its version; Bitwarden cloud does not.
 * Returns { version: string|null }.
 */
async function probeServerVersion(baseUrl, fetchImpl) {
  const doFetch = fetchImpl || globalThis.fetch.bind(globalThis);
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), REQUEST_TIMEOUT_MS);
    const res = await doFetch(baseUrl + '/api/config', { signal: ctrl.signal });
    clearTimeout(timer);
    if (!res.ok) return { version: null };
    const data = await res.json();
    return { version: typeof data.version === 'string' ? data.version : null };
  } catch (e) {
    return { version: null };
  }
}

module.exports = {
  BitwardenClient,
  BitwardenError,
  AuthError,
  resolveSafeServerUrl,
  probeServerVersion,
  internals: { isRestrictedAddress, isRestrictedIPv4, isRestrictedIPv6, v4ToInt }
};
