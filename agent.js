/**
 * agent.js — run one post past the moderation Agent and read its verdict.
 *
 * The agent is a PERSISTED resource created once by scripts/setup-agent.js. Its
 * id arrives via MODERATION_AGENT_ID; this file never creates one. Creating an
 * agent per request would orphan a resource on every post and throw away the
 * versioning that is the reason for using an agent at all.
 *
 * Each review is one Session: created with the post as its opening event, read
 * to completion, then deleted so sessions don't accumulate.
 *
 * ENV: ANTHROPIC_API_KEY, MODERATION_AGENT_ID, MODERATION_ENVIRONMENT_ID
 */

const { CATEGORIES } = require('./moderationPolicy');

const REVIEW_TIMEOUT_MS = 90000;

let client = null;
function getClient() {
  if (client) return client;
  if (!process.env.ANTHROPIC_API_KEY) return null;
  const Anthropic = require('@anthropic-ai/sdk');
  client = new Anthropic();
  return client;
}

function isConfigured() {
  return Boolean(
    process.env.ANTHROPIC_API_KEY &&
    process.env.MODERATION_AGENT_ID &&
    process.env.MODERATION_ENVIRONMENT_ID,
  );
}

/**
 * The agent is told to reply with bare JSON, but a chat-shaped response can
 * still arrive wrapped in prose or a code fence — there is no schema
 * enforcement on a session the way there is on a direct call. Pull out the
 * outermost object rather than trusting the whole string to parse.
 */
function extractVerdict(text) {
  if (!text) return null;
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start === -1 || end === -1 || end <= start) return null;
  try {
    const o = JSON.parse(text.slice(start, end + 1));
    if (typeof o.allowed !== 'boolean') return null;
    return {
      allowed: o.allowed,
      reason: o.allowed ? '' : String(o.reason ?? 'This message was not accepted.'),
      categories: Array.isArray(o.categories)
        ? o.categories.filter((c) => CATEGORIES.includes(c))
        : [],
    };
  } catch {
    return null;
  }
}

function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/**
 * @returns {Promise<{allowed:boolean, reason:string, categories:string[], sessionId:string|null}>}
 * @throws if the agent could not be reached or produced no usable verdict —
 *         callers must treat a throw as "do not publish".
 */
async function reviewPost(text) {
  const c = getClient();
  if (!c) throw new Error('ANTHROPIC_API_KEY is not set');

  const agentId = process.env.MODERATION_AGENT_ID;
  const environmentId = process.env.MODERATION_ENVIRONMENT_ID;
  if (!agentId || !environmentId) {
    throw new Error('MODERATION_AGENT_ID / MODERATION_ENVIRONMENT_ID are not set');
  }

  let session = null;
  try {
    // Passing the post as initial_events starts the agent in the same call, so
    // there is no separate "send the message" round trip.
    session = await withTimeout(
      c.beta.sessions.create({
        agent: agentId, // string form = latest published version
        environment_id: environmentId,
        title: 'Discussion post review',
        initial_events: [
          {
            type: 'user.message',
            content: [{ type: 'text', text: `<post>\n${text}\n</post>` }],
          },
        ],
      }),
      REVIEW_TIMEOUT_MS,
      'session create',
    );

    // Read the session to completion.
    const stream = await c.beta.sessions.events.stream(session.id);

    let answer = '';
    let errored = null;

    await withTimeout(
      (async () => {
        for await (const event of stream) {
          if (event.type === 'agent.message') {
            for (const block of event.content ?? []) {
              if (block.type === 'text') answer += block.text;
            }
          } else if (event.type === 'session.error') {
            errored = event.error?.message ?? 'session error';
            break;
          } else if (event.type === 'session.status_terminated') {
            break;
          } else if (event.type === 'session.status_idle') {
            // Idle is not the same as finished — the agent goes idle whenever
            // it is waiting on us. With no tools configured nothing should ever
            // ask, but breaking on a bare idle would truncate the read if it did.
            if (event.stop_reason?.type !== 'requires_action') break;
          }
        }
      })(),
      REVIEW_TIMEOUT_MS,
      'session read',
    );

    if (errored) throw new Error(errored);

    const verdict = extractVerdict(answer);
    if (!verdict) {
      throw new Error(`agent returned no usable verdict: ${answer.slice(0, 200)}`);
    }
    return { ...verdict, sessionId: session.id };
  } finally {
    // One session per post would otherwise pile up indefinitely. Best-effort —
    // a failed cleanup must never turn an allowed post into a rejected one.
    if (session?.id) {
      try {
        await c.beta.sessions.delete(session.id);
      } catch {
        /* non-fatal */
      }
    }
  }
}

module.exports = { reviewPost, isConfigured, extractVerdict };
