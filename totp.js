/**
 * totp.js — time-based one-time passwords (RFC 6238) and recovery codes.
 *
 * Hand-rolled on node:crypto rather than pulled from a package: it is about
 * forty lines of well-specified arithmetic, it costs nothing, it works offline,
 * and it means the thing guarding the admin panel has no supply chain.
 *
 * Compatible with Google Authenticator, Authy, 1Password, Microsoft
 * Authenticator — anything that speaks otpauth://.
 */

const crypto = require('crypto');

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const STEP_SECONDS = 30;
const DIGITS = 6;

function base32Encode(buf) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** A fresh 160-bit secret, in the base32 form authenticator apps expect. */
function generateSecret() {
  return base32Encode(crypto.randomBytes(20));
}

function hotp(secretBuf, counter) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const mac = crypto.createHmac('sha1', secretBuf).update(buf).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const bin =
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff);
  return String(bin % 10 ** DIGITS).padStart(DIGITS, '0');
}

function currentStep(now = Date.now()) {
  return Math.floor(now / 1000 / STEP_SECONDS);
}

function codeFor(secret, step) {
  return hotp(base32Decode(secret), step);
}

/**
 * Verify a code, allowing one step either side so a slightly wrong phone clock
 * still works.
 *
 * Returns the step the code belongs to, or null. The caller must record that
 * step and refuse to accept it twice — otherwise a code shoulder-surfed or
 * captured from a log stays usable for its full thirty seconds.
 */
function verify(secret, code, { now = Date.now(), window = 1, lastUsedStep = null } = {}) {
  const clean = String(code ?? '').replace(/\D/g, '');
  if (clean.length !== DIGITS) return null;
  const step = currentStep(now);
  for (let i = -window; i <= window; i++) {
    const s = step + i;
    if (lastUsedStep !== null && s <= lastUsedStep) continue; // already spent
    const expected = codeFor(secret, s);
    // Constant-time: a byte-by-byte comparison leaks how much of the code was
    // right through timing.
    const a = Buffer.from(expected);
    const b = Buffer.from(clean);
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) return s;
  }
  return null;
}

/** The URI an authenticator app reads from the QR code. */
function otpauthUri({ secret, account, issuer = 'DoseWise Admin' }) {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: String(DIGITS),
    period: String(STEP_SECONDS),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

// ── Recovery codes ──────────────────────────────────────────────────────────
// Without these, losing the phone means losing the admin panel permanently.

function generateRecoveryCodes(n = 8) {
  const codes = [];
  for (let i = 0; i < n; i++) {
    // Ambiguous characters left out so they can be written down and read back.
    const raw = crypto.randomBytes(5).toString('hex').toUpperCase();
    codes.push(`${raw.slice(0, 5)}-${raw.slice(5, 10)}`);
  }
  return codes;
}

const hashRecovery = (code) =>
  crypto.createHash('sha256').update(String(code).toUpperCase().replace(/[^A-Z0-9]/g, '')).digest('hex');

/** @returns the index of the matching hash, or -1. Single use — the caller
 *  must remove it. */
function matchRecovery(hashes, code) {
  const h = hashRecovery(code);
  return (hashes ?? []).findIndex((stored) => {
    const a = Buffer.from(stored ?? '', 'hex');
    const b = Buffer.from(h, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  });
}

module.exports = {
  generateSecret, verify, codeFor, currentStep, otpauthUri,
  generateRecoveryCodes, hashRecovery, matchRecovery,
  base32Encode, base32Decode, STEP_SECONDS, DIGITS,
};
