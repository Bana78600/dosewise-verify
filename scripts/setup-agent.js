/**
 * setup-agent.js — provision the moderation agent. RUN ONCE, not per request.
 *
 * Creates (or updates) the Managed Agent and the environment its sessions run
 * in, then prints the two IDs to put in the Render environment:
 *
 *   MODERATION_AGENT_ID
 *   MODERATION_ENVIRONMENT_ID
 *
 * Agents are persistent, versioned resources. Creating one per request would
 * accumulate orphaned agents, pay creation latency on every post, and defeat
 * the versioning that makes this worth doing at all.
 *
 *   node scripts/setup-agent.js                      # create
 *   node scripts/setup-agent.js --update <agent_id>  # publish a new version
 *
 * Requires ANTHROPIC_API_KEY.
 */

const Anthropic = require('@anthropic-ai/sdk');
const { MODEL, SYSTEM } = require('../moderationPolicy');

const AGENT_NAME = 'DoseWise Discussion Moderator';
const ENV_NAME = 'dosewise-moderation';

const updateIdx = process.argv.indexOf('--update');
const UPDATE_ID = updateIdx !== -1 ? process.argv[updateIdx + 1] : null;

(async () => {
  if (!process.env.ANTHROPIC_API_KEY) {
    console.error('FATAL: ANTHROPIC_API_KEY is not set.');
    process.exit(1);
  }
  const client = new Anthropic();

  // ── Environment ───────────────────────────────────────────────────────────
  // The moderator reads text and answers; it needs no network access and no
  // package installs, so lock egress down to nothing.
  let environment;
  const existing = await client.beta.environments.list();
  for (const e of existing.data ?? existing) {
    if (e.name === ENV_NAME) { environment = e; break; }
  }
  if (environment) {
    console.log(`environment reused: ${environment.id}`);
  } else {
    environment = await client.beta.environments.create({
      name: ENV_NAME,
      description: 'Sandbox for DoseWise discussion-board moderation sessions.',
      config: {
        type: 'cloud',
        networking: { type: 'limited' },
      },
    });
    console.log(`environment created: ${environment.id}`);
  }

  // ── Agent ─────────────────────────────────────────────────────────────────
  // No tools: the moderator's whole job is to read one post and return a
  // verdict. Giving it bash or web access would be latency and attack surface
  // for nothing.
  const config = {
    name: AGENT_NAME,
    description: 'Reviews posts to the DoseWise clinician discussion board and returns a publish/block verdict as JSON.',
    model: { id: MODEL, effort: 'low' },
    system: SYSTEM,
  };

  let agent;
  if (UPDATE_ID) {
    const current = await client.beta.agents.retrieve(UPDATE_ID);
    agent = await client.beta.agents.update(UPDATE_ID, { ...config, version: current.version });
    console.log(`agent updated: ${agent.id} -> version ${agent.version}`);
  } else {
    agent = await client.beta.agents.create(config);
    console.log(`agent created: ${agent.id} (version ${agent.version})`);
  }

  console.log('\nSet these on the Render service, then redeploy:\n');
  console.log(`  MODERATION_AGENT_ID=${agent.id}`);
  console.log(`  MODERATION_ENVIRONMENT_ID=${environment.id}`);
  console.log('\nTo change the moderation policy later, edit moderationPolicy.js and run:');
  console.log(`  node scripts/setup-agent.js --update ${agent.id}`);
  console.log('(sessions pick up the new version immediately — no server redeploy)');
  process.exit(0);
})().catch((e) => {
  console.error('setup failed:', e?.message ?? e);
  if (e?.status) console.error('status:', e.status);
  process.exit(1);
});
