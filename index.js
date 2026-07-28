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

const fs = require('fs');
const path = require('path');
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

// ── Admin panel ─────────────────────────────────────────────────────────────
// The page itself is public HTML — it contains no data and no secret. Every
// byte of actual information sits behind /admin/api, which requires a Firebase
// ID token carrying the `admin` custom claim.
app.use('/admin/api', require('./admin').build(admin, db));

app.get('/admin', (_req, res) => {
  const html = fs
    .readFileSync(path.join(__dirname, 'public', 'admin.html'), 'utf8')
    // The web API key is a public client identifier (it already ships inside
    // the Android app), not a credential. Injected rather than committed so it
    // tracks the deployment.
    .replace('__WEB_API_KEY__', process.env.FIREBASE_WEB_API_KEY || '');
  res.set('Content-Type', 'text/html; charset=utf-8');
  res.set('X-Robots-Tag', 'noindex, nofollow');
  res.send(html);
});

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

const MAX_POSTS_PER_HOUR = 15;
/** Reports needed before a post is pulled for review. */
const REPORTS_TO_HIDE = 3;

/** Rolling one-hour post limit, kept in one document per user. */
async function checkRateLimit(uid) {
  const ref = db.collection('rateLimits').doc(uid);
  const cutoff = Date.now() - 60 * 60 * 1000;
  const snap = await ref.get();
  const recent = ((snap.exists ? snap.data()?.posts : null) ?? []).filter((t) => t > cutoff);

  if (recent.length >= MAX_POSTS_PER_HOUR) {
    return {
      ok: false,
      reason: `You have posted ${MAX_POSTS_PER_HOUR} times in the last hour. Please wait a while before posting again.`,
    };
  }
  recent.push(Date.now());
  await ref.set({ posts: recent }, { merge: true });
  return { ok: true };
}

/**
 * POST /discussion/:id/vote — mark a post helpful, or take the mark back.
 *
 * Helpful-only, deliberately: a downvote would duplicate the report button and
 * invite pile-ons on the trainees asking naive questions, who are exactly the
 * people this board should keep comfortable.
 *
 * -> 200 { ok:true, score, voted }
 */
app.post('/discussion/:id/vote', async (req, res) => {
  try {
    const uid = await authenticate(req);
    if (!uid) return res.status(401).json({ ok: false, reason: 'Please sign in again.' });

    const profileSnap = await db.collection('users').doc(uid).get();
    if (!profileSnap.exists || !profileSnap.data()?.approved) {
      return res.status(403).json({ ok: false, reason: 'Your account is not verified yet.' });
    }

    const messageId = String(req.params.id || '').trim();
    if (!messageId) return res.status(400).json({ ok: false, reason: 'Missing message id.' });

    // You cannot vote up your own answer.
    const authorSnap = await db.collection('discussionAuthors').doc(messageId).get();
    if (authorSnap.exists && authorSnap.data()?.uid === uid) {
      return res.json({ ok: false, reason: 'You cannot mark your own post as helpful.' });
    }

    const msgRef = db.collection('discussions').doc(messageId);
    const voteRef = db.collection('votes').doc(`${messageId}__${uid}`);

    // A transaction, not a read-then-write: two members voting at the same
    // instant would both read the same score and the second would overwrite
    // the first, silently losing a vote.
    const result = await db.runTransaction(async (tx) => {
      const [msg, vote] = await Promise.all([tx.get(msgRef), tx.get(voteRef)]);
      if (!msg.exists) return { gone: true };

      const current = Number(msg.data()?.score ?? 0);
      if (vote.exists) {
        tx.delete(voteRef);
        tx.update(msgRef, { score: Math.max(0, current - 1) });
        return { score: Math.max(0, current - 1), voted: false };
      }
      tx.set(voteRef, {
        messageId,
        uid, // read back by the owner so the app can show which posts they marked
        at: admin.firestore.FieldValue.serverTimestamp(),
      });
      tx.update(msgRef, { score: current + 1 });
      return { score: current + 1, voted: true };
    });

    if (result.gone) return res.json({ ok: false, reason: 'That post is no longer available.' });
    return res.json({ ok: true, score: result.score, voted: result.voted });
  } catch (e) {
    console.error('vote error:', e);
    return res.status(500).json({ ok: false, reason: 'Could not record your vote. Please try again.' });
  }
});

/**
 * POST /discussion/:id/report
 * Headers: Authorization: Bearer <Firebase ID token>
 * -> 200 { ok:true, hidden:boolean }
 *
 * Members reporting each other is what covers the judgement calls no offline
 * filter can make — a post that is unprofessional without containing a single
 * listed word. Once enough distinct members report it, the post is moved out of
 * the board and into a server-only collection for review.
 */
app.post('/discussion/:id/report', async (req, res) => {
  try {
    const uid = await authenticate(req);
    if (!uid) return res.status(401).json({ ok: false, reason: 'Please sign in again.' });

    const profileSnap = await db.collection('users').doc(uid).get();
    if (!profileSnap.exists || !profileSnap.data()?.approved) {
      return res.status(403).json({ ok: false, reason: 'Your account is not verified yet.' });
    }

    const messageId = String(req.params.id || '').trim();
    if (!messageId) return res.status(400).json({ ok: false, reason: 'Missing message id.' });

    const msgRef = db.collection('discussions').doc(messageId);
    const msgSnap = await msgRef.get();
    if (!msgSnap.exists) return res.json({ ok: true, hidden: true }); // already gone

    // Nobody can report a post twice: the report id is the pair, so a repeat is
    // an overwrite rather than a second vote.
    const reportRef = db.collection('reports').doc(`${messageId}__${uid}`);
    const already = await reportRef.get();
    await reportRef.set({
      messageId,
      uid,
      at: admin.firestore.FieldValue.serverTimestamp(),
    });

    if (already.exists) {
      return res.json({ ok: true, hidden: false, alreadyReported: true });
    }

    const count = (await db.collection('reports').where('messageId', '==', messageId).get()).size;

    if (count >= REPORTS_TO_HIDE) {
      // Move it out of the board entirely rather than flagging it in place —
      // a `hidden` field would still be readable by anyone querying Firestore.
      const data = msgSnap.data();
      const authorSnap = await db.collection('discussionAuthors').doc(messageId).get();
      await db.collection('hiddenPosts').doc(messageId).set({
        ...data,
        authorUid: authorSnap.exists ? authorSnap.data()?.uid ?? null : null,
        reportCount: count,
        hiddenAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      await msgRef.delete();
      // Votes on a pulled post are meaningless and would otherwise linger.
      const stale = await db.collection('votes').where('messageId', '==', messageId).get();
      await Promise.all(stale.docs.map((d) => d.ref.delete().catch(() => {})));
      return res.json({ ok: true, hidden: true });
    }

    return res.json({ ok: true, hidden: false, reports: count });
  } catch (e) {
    console.error('report error:', e);
    return res.status(500).json({ ok: false, reason: 'Could not report this post. Please try again.' });
  }
});

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

    // Rate limit. Without an AI reviewer this is the main defence against
    // someone flooding the board faster than members can report it.
    const rl = await checkRateLimit(uid);
    if (!rl.ok) return res.json({ ok: false, reason: rl.reason });

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
      // Written explicitly so every post sorts consistently — a missing field
      // and a zero would order differently.
      score: 0,
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
