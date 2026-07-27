/**
 * dedupe-licences.js — find and resolve duplicate accounts sharing one PMDC
 * registration number, and backfill the `licences` claim table.
 *
 * The uniqueness check in index.js prevents NEW duplicates. It does not clean up
 * accounts created before it shipped, and until each licence is claimed the
 * table is empty — so whichever duplicate re-verifies first would take
 * ownership, which may not be the original account.
 *
 * Run REPORT-ONLY first (the default). Nothing is written without --apply.
 *
 *   node scripts/dedupe-licences.js            # report only
 *   node scripts/dedupe-licences.js --apply    # keep oldest, revoke the rest
 *
 * Requires FIREBASE_SERVICE_ACCOUNT in the environment, same as the server.
 */

const admin = require('firebase-admin');
const { norm } = require('../pmdc');

const APPLY = process.argv.includes('--apply');

const svc = process.env.FIREBASE_SERVICE_ACCOUNT;
if (!svc) {
  console.error('FATAL: FIREBASE_SERVICE_ACCOUNT is not set.');
  process.exit(1);
}
admin.initializeApp({ credential: admin.credential.cert(JSON.parse(svc)) });
const db = admin.firestore();

function createdMillis(data) {
  const t = data?.createdAt;
  if (t?.toMillis) return t.toMillis();
  return Number.MAX_SAFE_INTEGER; // undated accounts sort last, never "oldest"
}

(async () => {
  const snap = await db.collection('users').get();

  /** @type {Map<string, Array<{uid:string,email:string,fullName:string,licenseNumber:string,approved:boolean,created:number}>>} */
  const byLicence = new Map();

  snap.forEach((doc) => {
    const d = doc.data() || {};
    const key = norm(d.licenseNumber);
    if (!key) return;
    const list = byLicence.get(key) ?? [];
    list.push({
      uid: doc.id,
      email: d.email ?? '(no email)',
      fullName: d.fullName ?? '',
      licenseNumber: d.licenseNumber ?? '',
      approved: Boolean(d.approved),
      created: createdMillis(d),
    });
    byLicence.set(key, list);
  });

  const duplicates = [...byLicence.entries()].filter(([, list]) => list.length > 1);

  console.log(`Scanned ${snap.size} accounts across ${byLicence.size} registration numbers.`);
  console.log(`Duplicate registration numbers: ${duplicates.length}\n`);

  let wouldRevoke = 0;

  for (const [key, list] of duplicates) {
    // Oldest account wins. Prefer an already-approved one so we never revoke a
    // working account in favour of an unapproved older shell.
    const sorted = [...list].sort((a, b) => {
      if (a.approved !== b.approved) return a.approved ? -1 : 1;
      return a.created - b.created;
    });
    const keep = sorted[0];
    const revoke = sorted.slice(1);

    console.log(`Licence ${key} — ${list.length} accounts`);
    console.log(`  KEEP    ${keep.uid}  ${keep.email}  approved=${keep.approved}`);
    for (const r of revoke) {
      console.log(`  REVOKE  ${r.uid}  ${r.email}  approved=${r.approved}`);
      if (r.approved) wouldRevoke++;
    }
    console.log('');
  }

  // Backfill the claim table for every licence, duplicate or not, so the
  // rightful owner holds the claim before anyone re-verifies.
  const claims = [...byLicence.entries()].map(([key, list]) => {
    const sorted = [...list].sort((a, b) => {
      if (a.approved !== b.approved) return a.approved ? -1 : 1;
      return a.created - b.created;
    });
    return { key, owner: sorted[0] };
  });

  if (!APPLY) {
    console.log('--- REPORT ONLY. Nothing was written. ---');
    console.log(`Would claim ${claims.length} licences and revoke ${wouldRevoke} approved duplicate account(s).`);
    console.log('Re-run with --apply to make these changes.');
    process.exit(0);
  }

  let claimed = 0;
  let revoked = 0;

  for (const { key, owner } of claims) {
    await db.collection('licences').doc(key).set(
      {
        uid: owner.uid,
        registrationNo: owner.licenseNumber,
        claimedAt: admin.firestore.FieldValue.serverTimestamp(),
        backfilled: true,
      },
      { merge: true },
    );
    claimed++;
  }

  for (const [, list] of duplicates) {
    const sorted = [...list].sort((a, b) => {
      if (a.approved !== b.approved) return a.approved ? -1 : 1;
      return a.created - b.created;
    });
    for (const r of sorted.slice(1)) {
      // Revoke access but leave the account intact — the person can still sign
      // in and see why, and nothing is destroyed.
      await db.collection('users').doc(r.uid).set(
        {
          approved: false,
          lastVerification: {
            at: admin.firestore.FieldValue.serverTimestamp(),
            ok: false,
            reason: 'DUPLICATE_LICENCE_REVOKED',
          },
        },
        { merge: true },
      );
      revoked++;
    }
  }

  console.log(`--- APPLIED. Claimed ${claimed} licences, revoked ${revoked} duplicate account(s). ---`);
  process.exit(0);
})().catch((e) => {
  console.error('dedupe failed:', e);
  process.exit(1);
});
