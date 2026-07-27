/**
 * moderation.js — AI review of every discussion post before it is stored.
 *
 * WHY SERVER-SIDE: a check that runs on the phone is bypassed by anyone who
 * edits the app or calls Firestore directly. The Firestore rules forbid clients
 * from writing to `discussions` at all — only this service may, and only after
 * a message passes both the deterministic pre-filter and the Claude review.
 *
 * FAILS CLOSED: if the moderator cannot reach Claude, the post is REJECTED
 * rather than published unreviewed. On a clinician forum, an unmoderated post
 * is worse than a failed post.
 *
 * ENV: ANTHROPIC_API_KEY
 */

const MODEL = 'claude-opus-5';

/** Categories the reviewer may return. Keep in sync with the schema below. */
const CATEGORIES = [
  'profanity',
  'harassment',
  'unprofessional',
  'patient_identifiable',
  'personal_contact',
  'spam',
  'off_topic',
  'none',
];

// ── Deterministic pre-filter ────────────────────────────────────────────────
// Runs before the model: it is instant, free, and still works when the API is
// unreachable. Catches the mechanical cases (contact details) that are the
// whole point of "users can't see each other's personal details".

const PATTERNS = [
  { name: 'personal_contact', re: /[\w.+-]+@[\w-]+\.[\w.]{2,}/, label: 'an email address' },
  // Pakistani mobile (03xx-xxxxxxx), +92 form, and generic long digit runs.
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

// ── Claude reviewer ─────────────────────────────────────────────────────────

let client = null;
function getClient() {
  if (client) return client;
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) return null;
  const Anthropic = require('@anthropic-ai/sdk');
  client = new Anthropic({ apiKey: key });
  return client;
}

const SYSTEM = `You review messages posted to a private discussion board used by PMDC-registered doctors and anaesthesia trainees in Pakistan to discuss cases and learn from each other.

Your job is to decide whether a message may be posted. Be permissive about CLINICAL content and strict about the four things below.

BLOCK a message if it contains:
- profanity, insults, mockery, or personal attacks on any person or group
- unprofessional conduct: sexual content, discriminatory remarks, threats, or content that would embarrass the profession
- patient-identifiable information: a patient's name, hospital record/MR number, CNIC, exact date of birth, address, phone number, photograph description that identifies them, or any combination specific enough to identify one real person
- personal contact details of any user: email address, phone number, WhatsApp/Telegram handle, social media account, or a request to be contacted privately

ALLOW normal professional discussion, including:
- clinical detail, drug doses, complications, adverse outcomes, and deaths
- de-identified case descriptions ("a 45-year-old male, ASA III, for laparoscopic cholecystectomy")
- disagreement, criticism of a technique or a guideline, and blunt clinical language
- questions from trainees that reveal inexperience — this is a teaching board
- frank discussion of error and near-misses, which is how people learn

Discussing a drug, a dose, a complication, or a death is NOT unprofessional. Only block clinical content if it identifies a real patient.

Set allowed=false only if one of the four BLOCK categories clearly applies. When it is a borderline judgement call, allow the message.

In "reason", write one short sentence addressed to the author explaining what to change. Do not quote the offending text back. If allowed, leave reason empty.`;

const SCHEMA = {
  type: 'object',
  properties: {
    allowed: { type: 'boolean' },
    categories: { type: 'array', items: { type: 'string', enum: CATEGORIES } },
    reason: { type: 'string' },
  },
  required: ['allowed', 'categories', 'reason'],
  additionalProperties: false,
};

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('moderation timeout')), ms)),
  ]);
}

/**
 * @returns {Promise<{allowed:boolean, reason:string, categories:string[], stage:string}>}
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

  // 1. Deterministic checks first — instant, and independent of the API.
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

  // 2. Claude reviews the substance.
  const c = getClient();
  if (!c) {
    console.error('moderation: ANTHROPIC_API_KEY is not set — rejecting post.');
    return {
      allowed: false,
      reason: 'Message review is unavailable right now. Please try again shortly.',
      categories: ['none'],
      stage: 'unavailable',
    };
  }

  try {
    const res = await withTimeout(
      c.messages.create({
        model: MODEL,
        max_tokens: 1024,
        system: SYSTEM,
        // Low effort: this is a short classification, not a reasoning task, and
        // the author is waiting on the result.
        output_config: {
          effort: 'low',
          format: { type: 'json_schema', schema: SCHEMA },
        },
        messages: [
          {
            role: 'user',
            content: `Review this post:\n\n<post>\n${body}\n</post>`,
          },
        ],
      }),
      15000,
    );

    // A refusal carries no usable content — treat it as "do not publish".
    if (res.stop_reason === 'refusal') {
      return {
        allowed: false,
        reason: 'This message could not be reviewed. Please rephrase it.',
        categories: ['none'],
        stage: 'refusal',
      };
    }

    const block = res.content.find((b) => b.type === 'text');
    const parsed = JSON.parse(block.text);

    return {
      allowed: Boolean(parsed.allowed),
      reason: parsed.allowed ? '' : String(parsed.reason || 'This message was not accepted.'),
      categories: Array.isArray(parsed.categories) ? parsed.categories : [],
      stage: 'model',
    };
  } catch (e) {
    // FAIL CLOSED. An unreviewed post is worse than a rejected one.
    console.error('moderation error:', e?.message ?? e);
    return {
      allowed: false,
      reason: 'Message review is unavailable right now. Please try again shortly.',
      categories: ['none'],
      stage: 'error',
    };
  }
}

module.exports = { moderate, preFilter, CATEGORIES };
