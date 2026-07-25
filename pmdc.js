/**
 * pmdc.js — PMDC (Pakistan Medical & Dental Council) licence verification.
 *
 * Uses the public register API that pmdc.pk's own "Search for Doctors" form calls:
 *   POST https://hospitals-inspections.pmdc.pk/api/DRC/GetData
 *   body: RegistrationNo | Name | FatherName  (form-urlencoded)
 *   -> { status: true, data: [ { RegistrationNo, Name, FatherName, Gender,
 *        RegistrationType, RegistrationDate, ValidUpto, Status, ... } ] }
 *
 * SAFETY NOTES (learned from the real dataset):
 *  - Status is free text and inconsistent: "ACTIVE", "Active", "active",
 *    ".ACTIVE.", but ALSO "In Active" and "IN-ACTIVE". A substring test for
 *    "ACTIVE" would wrongly pass INACTIVE doctors — so we compare for EXACT
 *    equality after normalising away case and non-letters.
 *  - Many other states exist (Suspended…, Cancelled…, "Shifted to…",
 *    "Migrated to…"). Anything that is not exactly ACTIVE is rejected.
 *  - ValidUpto (DD/MM/YYYY) can be in the past even when Status says ACTIVE,
 *    so an expired licence is rejected too.
 */

const PMDC_URL = 'https://hospitals-inspections.pmdc.pk/api/DRC/GetData';

/** Collapse to letters+digits, uppercased. "In Active" -> "INACTIVE". */
function norm(s) {
  return String(s ?? '').toUpperCase().replace(/[^A-Z0-9]/g, '');
}

/** True only for an exactly-ACTIVE status (never for INACTIVE/SUSPENDED/etc). */
function isActiveStatus(status) {
  return norm(status) === 'ACTIVE';
}

/** Name tokens, minus honorifics and noise, for tolerant comparison. */
const TITLES = new Set(['DR', 'DOCTOR', 'PROF', 'PROFESSOR', 'MR', 'MRS', 'MS', 'MISS', 'MUHAMMAD', 'MOHAMMAD', 'MD']);
function nameTokens(name) {
  return String(name ?? '')
    .toUpperCase()
    .replace(/[^A-Z\s]/g, ' ')
    .split(/\s+/)
    .filter((t) => t.length > 1 && !TITLES.has(t));
}

/**
 * Tolerant name match, order-independent.
 *
 * Rule: every meaningful token of the SHORTER name must appear in the longer
 * one. This tolerates extra name parts on either side — "Ahmad Hassan Ul Bana"
 * still matches a register entry of "AHMAD HASSAN", and vice versa — which
 * matters because people rarely type their name exactly as PMDC stores it.
 * The registration number is the real key; this is a sanity check that the
 * applicant isn't pasting a stranger's number.
 */
function namesMatch(entered, registered) {
  const a = nameTokens(entered);
  const b = nameTokens(registered);
  if (a.length === 0 || b.length === 0) return false;
  const [short, long] = a.length <= b.length ? [a, b] : [b, a];
  const longSet = new Set(long);
  return short.every((t) => longSet.has(t));
}

/** Parse PMDC's DD/MM/YYYY. Returns null if absent/unparseable. */
function parseValidUpto(s) {
  const m = String(s ?? '').trim().match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
  if (!m) return null;
  const [, d, mo, y] = m;
  const dt = new Date(Number(y), Number(mo) - 1, Number(d));
  return isNaN(dt.getTime()) ? null : dt;
}

async function queryPmdc(registrationNo) {
  const body = new URLSearchParams({
    RegistrationNo: String(registrationNo || '').trim(),
    Name: '',
    FatherName: '',
  });
  const res = await fetch(PMDC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
    body,
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) throw new Error(`PMDC responded ${res.status}`);
  return res.json();
}

/**
 * Verify a licence.
 * @returns {Promise<{ok:boolean, reason?:string, record?:object}>}
 */
async function verifyLicence({ registrationNo, fullName }) {
  if (!registrationNo || !String(registrationNo).trim()) {
    return { ok: false, reason: 'Please enter your PMDC registration number.' };
  }

  let json;
  try {
    json = await queryPmdc(registrationNo);
  } catch (e) {
    // Register unreachable — do NOT approve, but say so distinctly so the app
    // can offer "try again later" rather than "your licence is invalid".
    return { ok: false, reason: 'UNAVAILABLE', detail: e?.message };
  }

  const rows = Array.isArray(json?.data) ? json.data : [];
  if (rows.length === 0) {
    return { ok: false, reason: 'No PMDC record found for that registration number. Please check and re-enter it.' };
  }

  // Prefer an exact registration-number match if the API returned several.
  const exact = rows.find((r) => norm(r.RegistrationNo) === norm(registrationNo));
  const rec = exact || rows[0];

  if (!isActiveStatus(rec.Status)) {
    return {
      ok: false,
      reason: `This PMDC licence is not active (status: ${String(rec.Status).trim()}). Access requires an active licence.`,
      record: rec,
    };
  }

  const validUpto = parseValidUpto(rec.ValidUpto);
  if (validUpto) {
    const today = new Date(); today.setHours(0, 0, 0, 0);
    if (validUpto < today) {
      return {
        ok: false,
        reason: `This PMDC licence expired on ${rec.ValidUpto}. Please renew it and try again.`,
        record: rec,
      };
    }
  }

  if (!namesMatch(fullName, rec.Name)) {
    return {
      ok: false,
      reason: 'The name you entered does not match the name registered against that PMDC number. Please enter your name exactly as registered with PMDC.',
      record: rec,
    };
  }

  return { ok: true, record: rec };
}

module.exports = { verifyLicence, isActiveStatus, namesMatch, parseValidUpto, norm };
