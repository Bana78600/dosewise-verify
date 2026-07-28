/**
 * make-admin.js — grant (or revoke) admin rights on an account.
 *
 * Admin status is a Firebase CUSTOM CLAIM, not a Firestore field. The claim is
 * baked into the signed ID token, so the server can trust it without a database
 * lookup and no client can forge or self-assign it. A plain document could be
 * read by the client and would tempt someone into checking it app-side, which
 * is exactly the mistake that makes admin panels fall over.
 *
 *   node scripts/make-admin.js ahub07@gmail.com
 *   node scripts/make-admin.js ahub07@gmail.com --revoke
 *
 * Requires FIREBASE_SERVICE_ACCOUNT.
 *
 * The account must already exist — sign up in the app first.
 */

const admin = require('firebase-admin');

const email = process.argv[2];
const REVOKE = process.argv.includes('--revoke');

if (!email || email.startsWith('--')) {
  console.error('Usage: node scripts/make-admin.js <email> [--revoke]');
  process.exit(1);
}

const svc = process.env.FIREBASE_SERVICE_ACCOUNT;
if (!svc) {
  console.error('FATAL: FIREBASE_SERVICE_ACCOUNT is not set.');
  process.exit(1);
}
admin.initializeApp({ credential: admin.credential.cert(JSON.parse(svc)) });

(async () => {
  let user;
  try {
    user = await admin.auth().getUserByEmail(email);
  } catch {
    console.error(`No account found for ${email}. Sign up in the app first, then re-run this.`);
    process.exit(1);
  }

  const existing = user.customClaims ?? {};
  await admin.auth().setCustomUserClaims(user.uid, { ...existing, admin: !REVOKE });

  // Mirrored for display only — the claim above is what actually grants access.
  await admin.firestore().collection('users').doc(user.uid).set(
    { isAdmin: !REVOKE, adminChangedAt: admin.firestore.FieldValue.serverTimestamp() },
    { merge: true },
  );

  // Existing sessions carry the OLD claim until their token refreshes (up to an
  // hour). Revoking forces an immediate re-authentication, which matters when
  // you are taking rights away rather than handing them out.
  if (REVOKE) await admin.auth().revokeRefreshTokens(user.uid);

  console.log(`${REVOKE ? 'Revoked admin from' : 'Granted admin to'} ${email} (${user.uid})`);
  if (!REVOKE) {
    console.log('Sign out and back in on the admin panel to pick up the new rights.');
  }
  process.exit(0);
})().catch((e) => {
  console.error('failed:', e?.message ?? e);
  process.exit(1);
});
