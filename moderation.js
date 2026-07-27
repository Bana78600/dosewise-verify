/**
 * moderation.js — review of every discussion post before it is stored.
 *
 * Two stages:
 *   1. a deterministic pre-filter — instant, free, and still works when the
 *      API is unreachable
 *   2. the moderation AGENT (see agent.js) — a persisted, versioned Managed
 *      Agent, not a direct model call, so the policy can be retuned and
 *      rolled back from the Console without redeploying this server, and every
 *      decision leaves an inspectable session trace
 *
 * WHY SERVER-SIDE: a check that runs on the phone is bypassed by anyone who
 * edits the app or calls Firestore directly. The Firestore rules forbid clients
 * from writing to `discussions` at all — only this service may, and only after
 * a message passes both stages.
 *
 * FAILS CLOSED: if the agent cannot be reached, the post is REJECTED rather
 * than published unreviewed. On a clinician forum, an unmoderated post is worse
 * than a failed post.
 */

const { reviewPost, isConfigured } = require('./agent');
const { CATEGORIES } = require('./moderationPolicy');

// ── Deterministic pre-filter ────────────────────────────────────────────────
// Runs before the agent: instant, free, independent of the API, and it catches
// the mechanical cases (contact details) that are the whole point of "users
// can't see each other's personal details". Also keeps the agent's cost down —
// a post rejected here never reaches it.

const PATTERNS = [
  { name: 'personal_contact', re: /[\w.+-]+@[\w-]+\.[\w.]{2,}/, label: 'an email address' },
  // Pakistani mobile (03xx-xxxxxxx) and +92 form.
  { name: 'personal_contact', re: /(?:\+?92|0)\s?3\d{2}[\s-]?\d{7}/, label: 'a phone number' },
  { name: 'personal_contact', re: /\b\d{5}-\d{7}-\d\b/, label: 'a CNIC number' },
  { name: 'personal_contact', re: /\b(?:wa\.me|whatsapp|t\.me|telegram)\b/i, label: 'a messaging handle' },
  { name: 'personal_contact', re: /https?:\/\/\S+/i, label: 'a link' },
  // MR / hospital record numbers are the most common way a real patient gets
  // identified in a case discussion.
  { name: 'patient_identifiable', re: /\b(?:mr|mrn|reg|file)[\s.#:-]*\d{4,}\b/i, label: 'a patient record number' },
];

function preFilter(text) {
  const hits = [];
  for (const p of PATTERNS) {
    if (p.re.test(text)) hits.push({ category: p.name, label: p.label });
  }
  return hits;
}

/**
 * @returns {Promise<{allowed:boolean, reason:string, categories:string[], stage:string, sessionId?:string}>}
 */
async function moderate(text) {
  const body = String(text ?? '').trim();

  if (!body) {
    return { allowed: false, reason: 'Your message is empty.', categories: ['none'], stage: 'local' };
  }
  if (body.length > 2000) {
    return {
      allowed: false,
      reason: 'Please keep posts under 2000 characters.',
      categories: ['none'],
      stage: 'local',
    };
  }

  // 1. Deterministic checks first.
  const hits = preFilter(body);
  if (hits.length) {
    const labels = [...new Set(hits.map((h) => h.label))].join(' and ');
    return {
      allowed: false,
      reason: `Your message looks like it contains ${labels}. Please remove it — this board does not allow contact details or anything that could identify a patient.`,
      categories: [...new Set(hits.map((h) => h.category))],
      stage: 'prefilter',
    };
  }

  // 2. The agent reviews the substance.
  if (!isConfigured()) {
    console.error(
      'moderation: agent not configured — need ANTHROPIC_API_KEY, MODERATION_AGENT_ID and MODERATION_ENVIRONMENT_ID. Rejecting post.',
    );
    return {
      allowed: false,
      reason: 'Message review is unavailable right now. Please try again shortly.',
      categories: ['none'],
      stage: 'unavailable',
    };
  }

  try {
    const verdict = await reviewPost(body);
    return {
      allowed: verdict.allowed,
      reason: verdict.reason,
      categories: verdict.categories,
      stage: 'agent',
      sessionId: verdict.sessionId,
    };
  } catch (e) {
    // FAIL CLOSED. An unreviewed post is worse than a rejected one.
    console.error('moderation agent error:', e?.message ?? e);
    return {
      allowed: false,
      reason: 'Message review is unavailable right now. Please try again shortly.',
      categories: ['none'],
      stage: 'error',
    };
  }
}

module.exports = { moderate, preFilter, CATEGORIES };
