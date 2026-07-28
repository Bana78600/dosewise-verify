/**
 * admin.js — the management API behind the admin panel.
 *
 * EVERY route here is gated by `requireAdmin`, which verifies the Firebase ID
 * token AND the `admin` custom claim on it. The claim is signed by Firebase, so
 * a client cannot forge it. Nothing is trusted from the request body.
 *
 * DEANONYMISATION POLICY: the author of an anonymous post is deliberately NOT
 * exposed on the normal board listing. It is exposed only for posts that
 * members have already reported and pulled, where acting on abuse requires
 * knowing whose account it was. Members are asked to admit clinical errors here;
 * "anonymous" has to mean something.
 */

const crypto = require('crypto');
const express = require('express');
const QRCode = require('qrcode');
const totp = require('./totp');

const SESSION_HOURS = 8;
const MAX_CODE_ATTEMPTS = 8;

function build(admin, db, sessionSecret) {
  const router = express.Router();

  // ── Second-factor session tokens ──────────────────────────────────────────
  // Passing the code proves possession of the phone; this token is the receipt.
  // Signed with a key derived from the service account, so it survives a
  // redeploy without needing another environment variable to be set.

  const b64u = (b) => Buffer.from(b).toString('base64url');
  const sign = (payload) =>
    crypto.createHmac('sha256', sessionSecret).update(payload).digest('base64url');

  function issueSession(uid) {
    const payload = b64u(JSON.stringify({ uid, exp: Date.now() + SESSION_HOURS * 3600 * 1000 }));
    return `${payload}.${sign(payload)}`;
  }

  function readSession(token) {
    const [payload, sig] = String(token ?? '').split('.');
    if (!payload || !sig) return null;
    const expected = sign(payload);
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    try {
      const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
      if (!data.exp || data.exp < Date.now()) return null;
      return data;
    } catch {
      return null;
    }
  }

  /**
   * First gate: who you are. Verifies the Firebase ID token and the admin
   * claim. This alone is NOT enough to reach any data.
   */
  async function requireAdminIdentity(req, res, next) {
    const authz = req.headers.authorization || '';
    const idToken = authz.startsWith('Bearer ') ? authz.slice(7) : null;
    if (!idToken) return res.status(401).json({ ok: false, reason: 'Not signed in.' });
    try {
      // checkRevoked: a revoked admin is locked out immediately rather than
      // staying live until their token happens to expire.
      const decoded = await admin.auth().verifyIdToken(idToken, true);
      if (!decoded.admin) return res.status(403).json({ ok: false, reason: 'Not an administrator.' });
      req.adminUid = decoded.uid;
      req.adminEmail = decoded.email ?? null;
      return next();
    } catch {
      return res.status(401).json({ ok: false, reason: 'Session expired. Please sign in again.' });
    }
  }

  /**
   * Second gate: possession of the enrolled authenticator. A stolen password —
   * even one that gets a genuine, correctly-claimed Firebase token — stops here.
   *
   * Enrolment is compulsory: an admin who has not set up an authenticator can
   * reach the enrolment routes and nothing else, so there is no window in which
   * a password alone is sufficient.
   */
  async function requireSecondFactor(req, res, next) {
    const snap = await db.collection('adminSecrets').doc(req.adminUid).get();
    if (!snap.exists || !snap.data()?.secret) {
      return res.status(428).json({ ok: false, code: 'ENROL_2FA', reason: 'Set up two-factor authentication to continue.' });
    }
    const session = readSession(req.headers['x-admin-2fa']);
    if (!session || session.uid !== req.adminUid) {
      return res.status(401).json({ ok: false, code: 'NEED_2FA', reason: 'Enter your authenticator code.' });
    }
    return next();
  }

  router.use(requireAdminIdentity);

  // ── Two-factor enrolment and verification ─────────────────────────────────
  // These sit BELOW the identity gate but ABOVE the second-factor gate — they
  // are the only routes reachable with a password alone.

  const secretRef = (uid) => db.collection('adminSecrets').doc(uid);

  router.get('/2fa/status', async (req, res) => {
    const snap = await secretRef(req.adminUid).get();
    const d = snap.exists ? snap.data() : null;
    res.json({
      ok: true,
      enrolled: Boolean(d?.secret),
      recoveryRemaining: (d?.recovery ?? []).length,
      sessionValid: Boolean(readSession(req.headers['x-admin-2fa'])),
    });
  });

  router.post('/2fa/enrol', async (req, res) => {
    const snap = await secretRef(req.adminUid).get();
    if (snap.exists && snap.data()?.secret) {
      return res.json({ ok: false, reason: 'Two-factor authentication is already set up.' });
    }
    const secret = totp.generateSecret();
    const uri = totp.otpauthUri({ secret, account: req.adminEmail ?? req.adminUid });
    // Held as `pending` until a code proves the app actually scanned it —
    // storing it as live would lock the admin out if the scan silently failed.
    await secretRef(req.adminUid).set(
      { pending: secret, pendingAt: admin.firestore.FieldValue.serverTimestamp() },
      { merge: true },
    );
    res.json({ ok: true, secret, uri, qr: await QRCode.toDataURL(uri, { margin: 1, width: 220 }) });
  });

  router.post('/2fa/confirm', async (req, res) => {
    const snap = await secretRef(req.adminUid).get();
    const pending = snap.exists ? snap.data()?.pending : null;
    if (!pending) return res.json({ ok: false, reason: 'Start the setup again.' });

    const step = totp.verify(pending, req.body?.code);
    if (step === null) return res.json({ ok: false, reason: 'That code is not right. Check the six digits and try again.' });

    const recovery = totp.generateRecoveryCodes(8);
    await secretRef(req.adminUid).set(
      {
        secret: pending,
        pending: admin.firestore.FieldValue.delete(),
        recovery: recovery.map(totp.hashRecovery),
        lastUsedStep: step,
        attempts: 0,
        enrolledAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true },
    );
    await audit(req, '2fa.enrol', req.adminEmail);
    // Shown once and never again — only hashes are kept.
    res.json({ ok: true, recoveryCodes: recovery, session: issueSession(req.adminUid) });
  });

  router.post('/2fa/verify', async (req, res) => {
    const ref = secretRef(req.adminUid);
    const snap = await ref.get();
    const d = snap.exists ? snap.data() : null;
    if (!d?.secret) return res.status(428).json({ ok: false, code: 'ENROL_2FA', reason: 'Set up two-factor authentication first.' });

    if ((d.attempts ?? 0) >= MAX_CODE_ATTEMPTS) {
      return res.json({ ok: false, reason: 'Too many incorrect codes. Use a recovery code, or wait and try again later.' });
    }

    // lastUsedStep is what stops a code being replayed inside its 30 seconds.
    const step = totp.verify(d.secret, req.body?.code, { lastUsedStep: d.lastUsedStep ?? null });
    if (step === null) {
      await ref.set({ attempts: (d.attempts ?? 0) + 1 }, { merge: true });
      await audit(req, '2fa.failed', req.adminEmail);
      return res.json({ ok: false, reason: 'That code is not right, or has already been used.' });
    }
    await ref.set({ lastUsedStep: step, attempts: 0 }, { merge: true });
    res.json({ ok: true, session: issueSession(req.adminUid) });
  });

  router.post('/2fa/recovery', async (req, res) => {
    const ref = secretRef(req.adminUid);
    const snap = await ref.get();
    const d = snap.exists ? snap.data() : null;
    if (!d?.secret) return res.status(428).json({ ok: false, code: 'ENROL_2FA', reason: 'Set up two-factor authentication first.' });

    const idx = totp.matchRecovery(d.recovery, req.body?.code);
    if (idx === -1) {
      await audit(req, '2fa.recovery_failed', req.adminEmail);
      return res.json({ ok: false, reason: 'That recovery code is not valid.' });
    }
    // Single use.
    const remaining = [...(d.recovery ?? [])];
    remaining.splice(idx, 1);
    await ref.set({ recovery: remaining, attempts: 0 }, { merge: true });
    await audit(req, '2fa.recovery_used', `${remaining.length} left`);
    res.json({ ok: true, session: issueSession(req.adminUid), remaining: remaining.length });
  });

  // Everything past this point needs the second factor.
  router.use(requireSecondFactor);

  const ts = (v) => (v?.toDate ? v.toDate().toISOString() : null);

  /** Record who did what. An admin action should never be untraceable. */
  async function audit(req, action, detail) {
    await db.collection('adminLog').add({
      action,
      detail: detail ?? null,
      byUid: req.adminUid,
      byEmail: req.adminEmail,
      at: admin.firestore.FieldValue.serverTimestamp(),
    }).catch(() => {});
  }

  // ── Overview ──────────────────────────────────────────────────────────────
  router.get('/overview', async (_req, res) => {
    const [users, posts, hidden, licences] = await Promise.all([
      db.collection('users').get(),
      db.collection('discussions').get(),
      db.collection('hiddenPosts').get(),
      db.collection('licences').get(),
    ]);
    let approved = 0;
    let pending = 0;
    users.forEach((d) => (d.data()?.approved ? approved++ : pending++));
    res.json({
      ok: true,
      users: users.size,
      approved,
      pending,
      posts: posts.size,
      hidden: hidden.size,
      licences: licences.size,
    });
  });

  // ── Accounts ──────────────────────────────────────────────────────────────
  router.get('/users', async (req, res) => {
    const q = String(req.query.q ?? '').trim().toLowerCase();
    const snap = await db.collection('users').get();
    const rows = [];
    snap.forEach((d) => {
      const v = d.data() ?? {};
      const row = {
        uid: d.id,
        email: v.email ?? null,
        fullName: v.fullName ?? '',
        licenseNumber: v.licenseNumber ?? '',
        approved: Boolean(v.approved),
        isAdmin: Boolean(v.isAdmin),
        createdAt: ts(v.createdAt),
        pmdcStatus: v.pmdc?.status ?? null,
        pmdcValidUpto: v.pmdc?.validUpto ?? null,
        lastVerification: v.lastVerification?.reason ?? (v.lastVerification?.ok ? 'ok' : null),
      };
      if (
        !q ||
        row.email?.toLowerCase().includes(q) ||
        row.fullName.toLowerCase().includes(q) ||
        row.licenseNumber.toLowerCase().includes(q)
      ) rows.push(row);
    });
    rows.sort((a, b) => (b.createdAt ?? '').localeCompare(a.createdAt ?? ''));
    res.json({ ok: true, rows: rows.slice(0, 300), total: snap.size });
  });

  router.post('/users/:uid/approved', async (req, res) => {
    const { uid } = req.params;
    const approved = Boolean(req.body?.approved);
    if (uid === req.adminUid && !approved) {
      return res.json({ ok: false, reason: 'You cannot revoke your own access from here.' });
    }
    await db.collection('users').doc(uid).set(
      {
        approved,
        lastVerification: {
          at: admin.firestore.FieldValue.serverTimestamp(),
          ok: approved,
          reason: approved ? 'ADMIN_APPROVED' : 'ADMIN_REVOKED',
        },
      },
      { merge: true },
    );
    await audit(req, approved ? 'user.approve' : 'user.revoke', uid);
    res.json({ ok: true });
  });

  // ── Licence claims ────────────────────────────────────────────────────────
  // This is the lockout escape hatch: one PMDC number binds to one account, so
  // a clinician who loses their email cannot re-register without releasing it.
  router.get('/licences', async (_req, res) => {
    const snap = await db.collection('licences').get();
    const rows = [];
    for (const d of snap.docs) {
      const v = d.data() ?? {};
      const owner = v.uid ? await db.collection('users').doc(v.uid).get() : null;
      rows.push({
        key: d.id,
        registrationNo: v.registrationNo ?? d.id,
        uid: v.uid ?? null,
        email: owner?.exists ? owner.data()?.email ?? null : null,
        claimedAt: ts(v.claimedAt),
        backfilled: Boolean(v.backfilled),
      });
    }
    rows.sort((a, b) => (b.claimedAt ?? '').localeCompare(a.claimedAt ?? ''));
    res.json({ ok: true, rows });
  });

  router.delete('/licences/:key', async (req, res) => {
    const key = String(req.params.key);
    await db.collection('licences').doc(key).delete();
    await audit(req, 'licence.release', key);
    res.json({ ok: true });
  });

  // ── Board ─────────────────────────────────────────────────────────────────
  router.get('/posts', async (_req, res) => {
    const snap = await db.collection('discussions').orderBy('createdAt', 'desc').limit(200).get();
    const rows = snap.docs.map((d) => {
      const v = d.data() ?? {};
      return {
        id: d.id,
        text: v.text ?? '',
        // Author withheld for anonymous posts — see the policy note at the top.
        displayName: v.displayName ?? '',
        anonymous: Boolean(v.anonymous),
        score: Number(v.score ?? 0),
        createdAt: ts(v.createdAt),
      };
    });
    res.json({ ok: true, rows });
  });

  router.delete('/posts/:id', async (req, res) => {
    const id = String(req.params.id);
    const ref = db.collection('discussions').doc(id);
    const snap = await ref.get();
    if (snap.exists) {
      // Keep a copy rather than destroying it — an admin deletion should be
      // reviewable and reversible.
      const authorSnap = await db.collection('discussionAuthors').doc(id).get();
      await db.collection('hiddenPosts').doc(id).set({
        ...snap.data(),
        authorUid: authorSnap.exists ? authorSnap.data()?.uid ?? null : null,
        hiddenAt: admin.firestore.FieldValue.serverTimestamp(),
        hiddenBy: 'admin',
      });
      await ref.delete();
      const votes = await db.collection('votes').where('messageId', '==', id).get();
      await Promise.all(votes.docs.map((d) => d.ref.delete().catch(() => {})));
    }
    await audit(req, 'post.remove', id);
    res.json({ ok: true });
  });

  // ── Reported / pulled posts ───────────────────────────────────────────────
  router.get('/hidden', async (_req, res) => {
    const snap = await db.collection('hiddenPosts').orderBy('hiddenAt', 'desc').limit(200).get();
    const rows = [];
    for (const d of snap.docs) {
      const v = d.data() ?? {};
      // Identity IS shown here — these posts were pulled, and acting on abuse
      // requires knowing whose account it was.
      const owner = v.authorUid ? await db.collection('users').doc(v.authorUid).get() : null;
      rows.push({
        id: d.id,
        text: v.text ?? '',
        displayName: v.displayName ?? '',
        anonymous: Boolean(v.anonymous),
        authorUid: v.authorUid ?? null,
        authorEmail: owner?.exists ? owner.data()?.email ?? null : null,
        reportCount: Number(v.reportCount ?? 0),
        hiddenBy: v.hiddenBy ?? 'reports',
        hiddenAt: ts(v.hiddenAt),
      });
    }
    res.json({ ok: true, rows });
  });

  router.post('/hidden/:id/restore', async (req, res) => {
    const id = String(req.params.id);
    const ref = db.collection('hiddenPosts').doc(id);
    const snap = await ref.get();
    if (!snap.exists) return res.json({ ok: false, reason: 'Not found.' });
    const v = snap.data() ?? {};
    await db.collection('discussions').doc(id).set({
      text: v.text,
      displayName: v.displayName,
      anonymous: Boolean(v.anonymous),
      score: Number(v.score ?? 0),
      createdAt: v.createdAt ?? admin.firestore.FieldValue.serverTimestamp(),
    });
    // Clear the reports too, or the next single report re-pulls it instantly.
    const reports = await db.collection('reports').where('messageId', '==', id).get();
    await Promise.all(reports.docs.map((d) => d.ref.delete().catch(() => {})));
    await ref.delete();
    await audit(req, 'post.restore', id);
    res.json({ ok: true });
  });

  router.delete('/hidden/:id', async (req, res) => {
    const id = String(req.params.id);
    await db.collection('hiddenPosts').doc(id).delete();
    await db.collection('discussionAuthors').doc(id).delete().catch(() => {});
    const reports = await db.collection('reports').where('messageId', '==', id).get();
    await Promise.all(reports.docs.map((d) => d.ref.delete().catch(() => {})));
    await audit(req, 'post.purge', id);
    res.json({ ok: true });
  });

  // ── Logs ──────────────────────────────────────────────────────────────────
  router.get('/moderation-log', async (_req, res) => {
    const snap = await db.collection('moderationLog').orderBy('at', 'desc').limit(200).get();
    const rows = [];
    for (const d of snap.docs) {
      const v = d.data() ?? {};
      const owner = v.uid ? await db.collection('users').doc(v.uid).get() : null;
      rows.push({
        id: d.id,
        email: owner?.exists ? owner.data()?.email ?? null : null,
        categories: v.categories ?? [],
        stage: v.stage ?? '',
        at: ts(v.at),
      });
    }
    res.json({ ok: true, rows });
  });

  router.get('/admin-log', async (_req, res) => {
    const snap = await db.collection('adminLog').orderBy('at', 'desc').limit(200).get();
    res.json({
      ok: true,
      rows: snap.docs.map((d) => {
        const v = d.data() ?? {};
        return {
          id: d.id,
          action: v.action ?? '',
          detail: v.detail ?? '',
          byEmail: v.byEmail ?? '',
          at: ts(v.at),
        };
      }),
    });
  });

  return router;
}

module.exports = { build };
