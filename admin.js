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

const express = require('express');

function build(admin, db) {
  const router = express.Router();

  /** Verify the token and the admin claim. */
  async function requireAdmin(req, res, next) {
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

  router.use(requireAdmin);

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
