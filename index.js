/**
 * DoseWise licence-verification server (deploy to Render).
 *
 * WHY A SERVER: the Firestore rules forbid the app from setting `approved`.
 * If the phone decided its own approval, anyone could bypass verification by
 * editing the app or calling Firestore directly. Only this service — using the
 * Firebase Admin SDK — may grant access, and it does so only after the PMDC
 * register confirms an ACTIVE, unexpired licence matching the applicant's name.
 *
 * ENV VARS (set in Render dashboard):
 *   FIREBASE_SERVICE_ACCOUNT  – the service-account JSON, pasted as one line
 *   ALLOWED_ORIGIN            – optional CORS origin (default "*")
 */

const express = require('express');
const admin = require('firebase-admin');
const { verifyLicence } = require('./pmdc');

// ── Firebase Admin ───────────────────────────────────────────────────────────
const svc = process.env.FIREBASE_SERVICE_ACCOUNT;
if (!svc) {
  console.error('FATAL: FIREBASE_SERVICE_ACCOUNT env var is not set.');
  process.exit(1);
}
admin.initializeApp({ credential: admin.credential.cert(JSON.parse(svc)) });
const db = admin.firestore();

const app = express();
app.use(express.json());
app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', process.env.ALLOWED_ORIGIN || '*');
  res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.get('/health', (_req, res) => res.json({ ok: true }));

/**
 * POST /verify-licence
 * Headers: Authorization: Bearer <Firebase ID token>
 * Body:    { registrationNo, fullName }
 * -> 200 { approved:true }                     licence verified, access granted
 * -> 200 { approved:false, reason, retryable } not verified, reason shown to user
 */
app.post('/verify-licence', async (req, res) => {
  try {
    // 1. Authenticate the caller — must be a signed-in Firebase user.
    const authz = req.headers.authorization || '';
    const idToken = authz.startsWith('Bearer ') ? authz.slice(7) : null;
    if (!idToken) return res.status(401).json({ approved: false, reason: 'Not signed in.' });

    let decoded;
    try {
      decoded = await admin.auth().verifyIdToken(idToken);
    } catch {
      return res.status(401).json({ approved: false, reason: 'Session expired. Please sign in again.' });
    }
    const uid = decoded.uid;

    // 2. Check the licence against the PMDC register.
    const { registrationNo, fullName } = req.body || {};
    const result = await verifyLicence({ registrationNo, fullName });

    if (!result.ok) {
      // Register unreachable is transient — tell the app it may retry.
      if (result.reason === 'UNAVAILABLE') {
        return res.json({
          approved: false,
          retryable: true,
          reason: 'The PMDC register could not be reached right now. Please try again shortly.',
        });
      }
      // Record the failed attempt for auditability, but never grant access.
      await db.collection('users').doc(uid).set(
        { lastVerification: { at: admin.firestore.FieldValue.serverTimestamp(), ok: false, reason: result.reason } },
        { merge: true },
      );
      return res.json({ approved: false, reason: result.reason });
    }

    // 3. Verified — grant access and store what we verified against.
    const rec = result.record || {};
    await db.collection('users').doc(uid).set(
      {
        approved: true,
        licenseNumber: String(registrationNo).trim(),
        pmdc: {
          registrationNo: rec.RegistrationNo ?? null,
          name: rec.Name ?? null,
          status: rec.Status ?? null,
          validUpto: rec.ValidUpto ?? null,
          registrationType: rec.RegistrationType ?? null,
          verifiedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        lastVerification: { at: admin.firestore.FieldValue.serverTimestamp(), ok: true },
      },
      { merge: true },
    );

    return res.json({ approved: true });
  } catch (e) {
    console.error('verify-licence error:', e);
    return res.status(500).json({ approved: false, retryable: true, reason: 'Verification service error. Please try again.' });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`DoseWise verification server listening on ${port}`));
