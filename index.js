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
const { verifyLicence, norm } = require('./pmdc');
const { moderate } = require('./moderation');

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

/** Thrown inside the claim transaction when another account already holds the licence. */
class LicenceTaken extends Error {}

/**
 * Bind a PMDC registration number to exactly one account.
 *
 * One registration number = one clinician = one account. Without this, the same
 * doctor (or anyone who knows a doctor's name and number) could register any
 * number of accounts against the same licence.
 *
 * A TRANSACTION on a document keyed by the licence number — not a query over
 * `users` — is what makes this safe: two signups submitted at the same moment
 * would both pass a query check and both be approved, because neither would see
 * the other's write yet. Claiming a single document is atomic, so exactly one
 * of them wins.
 */
async function claimLicence(uid, registrationNo) {
  const key = norm(registrationNo);
  if (!key) return { ok: false, reason: 'Registration number is missing.' };

  const ref = db.collection('licences').doc(key);
  try {
    await db.runTransaction(async (tx) => {
      const snap = await tx.get(ref);
      const owner = snap.exists ? snap.data()?.uid : null;
      // Re-verifying your own account is fine; a different uid is not.
      if (owner && owner !== uid) throw new LicenceTaken();
      tx.set(
        ref,
        {
          uid,
          registrationNo: String(registrationNo).trim(),
          claimedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        { merge: true },
      );
    });
    return { ok: true };
  } catch (e) {
    if (e instanceof LicenceTaken) {
      return {
        ok: false,
        reason:
          'An account already exists for this PMDC registration number. Each registration number can only be used once — please sign in with the email you registered with, or use "Forgot password?" to recover it.',
      };
    }
    throw e;
  }
}

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

    // 3. The licence is valid — now check nobody else has already claimed it.
    //    This runs BEFORE approval, so a duplicate never gets access. It runs
    //    AFTER the PMDC check so an unverified caller cannot squat on a number
    //    they don't own.
    const claim = await claimLicence(uid, registrationNo);
    if (!claim.ok) {
      await db.collection('users').doc(uid).set(
        {
          lastVerification: {
            at: admin.firestore.FieldValue.serverTimestamp(),
            ok: false,
            reason: 'DUPLICATE_LICENCE',
          },
        },
        { merge: true },
      );
      return res.json({ approved: false, code: 'DUPLICATE_LICENCE', reason: claim.reason });
    }

    // 4. Verified and claimed — grant access and store what we verified against.
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

/** Resolve the caller's Firebase uid from the Authorization header. */
async function authenticate(req) {
  const authz = req.headers.authorization || '';
  const idToken = authz.startsWith('Bearer ') ? authz.slice(7) : null;
  if (!idToken) return null;
  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    return decoded.uid;
  } catch {
    return null;
  }
}

/** First name only — the board never shows a full name. */
function firstNameOf(fullName) {
  const parts = String(fullName ?? '').trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return 'Colleague';
  // Skip a leading title so "Dr Ahmad Hassan" shows as "Ahmad", not "Dr".
  const titles = new Set(['dr', 'dr.', 'prof', 'prof.', 'mr', 'mr.', 'ms', 'ms.', 'mrs', 'mrs.']);
  const first = titles.has(parts[0].toLowerCase()) && parts.length > 1 ? parts[1] : parts[0];
  return first.slice(0, 24);
}

/**
 * POST /discussion
 * Headers: Authorization: Bearer <Firebase ID token>
 * Body:    { text, anonymous }
 * -> 200 { ok:true, id }
 * -> 200 { ok:false, reason }   rejected by moderation, reason shown to user
 *
 * Clients cannot write to `discussions` directly (see firestore.rules), so this
 * is the only path a message can take, and every message passes moderation.
 */
app.post('/discussion', async (req, res) => {
  try {
    const uid = await authenticate(req);
    if (!uid) return res.status(401).json({ ok: false, reason: 'Please sign in again.' });

    // Only approved (PMDC-verified) clinicians may post.
    const profileSnap = await db.collection('users').doc(uid).get();
    const profile = profileSnap.exists ? profileSnap.data() : null;
    if (!profile?.approved) {
      return res.status(403).json({ ok: false, reason: 'Your account is not verified yet.' });
    }

    const { text, anonymous } = req.body || {};

    const verdict = await moderate(text);
    if (!verdict.allowed) {
      // Record rejections so repeat offenders are visible, without storing the
      // rejected text itself.
      await db.collection('moderationLog').add({
        uid,
        categories: verdict.categories,
        stage: verdict.stage,
        // Links the rejection to its agent session trace in the Console, so a
        // disputed decision can actually be looked at.
        sessionId: verdict.sessionId ?? null,
        at: admin.firestore.FieldValue.serverTimestamp(),
      });
      return res.json({ ok: false, reason: verdict.reason });
    }

    const body = String(text).trim();
    const isAnon = Boolean(anonymous);
    const ref = db.collection('discussions').doc();

    // The PUBLIC document deliberately carries no uid, email, licence number or
    // full name — only a first name (or "Anonymous"). Firestore documents are
    // readable all-or-nothing, so an author field here would be visible to
    // every reader.
    await ref.set({
      text: body,
      displayName: isAnon ? 'Anonymous' : firstNameOf(profile.fullName),
      anonymous: isAnon,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // Authorship is stored separately, in a collection no client can read, so
    // abuse can still be traced without exposing who wrote what.
    await db.collection('discussionAuthors').doc(ref.id).set({
      uid,
      // Kept here rather than on the public message so the approval trace is
      // auditable without being visible to other members.
      moderationSessionId: verdict.sessionId ?? null,
      at: admin.firestore.FieldValue.serverTimestamp(),
    });

    return res.json({ ok: true, id: ref.id });
  } catch (e) {
    console.error('discussion error:', e);
    return res.status(500).json({ ok: false, reason: 'Could not post right now. Please try again.' });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`DoseWise verification server listening on ${port}`));
