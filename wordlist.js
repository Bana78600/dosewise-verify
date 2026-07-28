/**
 * wordlist.js — offline abuse detection. No API, no cost, no data leaves the
 * server, nothing to expire.
 *
 * Covers English and Roman-Urdu abuse, since this board is Pakistani and an
 * English-only list would miss most of what actually gets typed.
 *
 * ── Two design decisions worth understanding ───────────────────────────────
 *
 * 1. Runs of a letter are only collapsed at THREE or more ("fuuuck" -> "fuck").
 *    Collapsing doubles would fold "ass" into "as" and flag the word "as" in
 *    every message ever posted. Doubled letters are ordinary English
 *    (assessment, pressure, abscess); tripled letters are nearly always
 *    emphasis or evasion.
 *
 * 2. Words are matched WHOLE, never as substrings, so "analgesia",
 *    "analysis", "assessment" and "assisted" stay clean. Only a handful of
 *    unambiguous compounds are matched anywhere.
 *
 * ── Severe vs mild ─────────────────────────────────────────────────────────
 * This is a teaching board where people are meant to discuss their own errors.
 * "I made a stupid mistake" must post; "you are stupid" must not. MILD terms
 * are therefore allowed when the sentence is clearly self-directed, and
 * blocked otherwise. SEVERE terms are blocked either way.
 */

const LEET = {
  '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b',
  '@': 'a', '$': 's', '!': 'i', '|': 'i', '+': 't',
};

/**
 * lowercase -> leet-fold -> handle punctuation.
 *
 * Punctuation has to be read BOTH ways and neither alone is enough:
 *   'split'  turns it into a space, so "idiot,you" still yields "idiot"
 *   'strip'  deletes it, so the censored "f*ck" yields "fck"
 * Reading it only as a separator misses every asterisked swear word; reading it
 * only as deletable glues words together and misses the ones after a comma.
 */
function normalise(s, mode = 'split') {
  const lowered = String(s ?? '').toLowerCase();
  let out = '';
  for (const ch of lowered) out += LEET[ch] ?? ch;
  const replacement = mode === 'strip' ? '' : ' ';
  return out.replace(/[^a-z0-9\s]/g, replacement).replace(/\s+/g, ' ').trim();
}

/** Runs of THREE or more only — see design note 1. */
function collapse(s) {
  return s.replace(/(.)\1{2,}/g, '$1');
}

/** "f u c k" -> "fuck", without joining ordinary words together. */
function despace(s) {
  return s.replace(/\b(?:[a-z]\s){2,}[a-z]\b/g, (m) => m.replace(/\s/g, ''));
}

// Always blocked.
const SEVERE = [
  // English
  'fuck', 'fucks', 'fucking', 'fucker', 'fuckers', 'fuk', 'fck', 'fuc',
  'shit', 'shits', 'shitty', 'bullshit',
  'bitch', 'bitches', 'bastard', 'bastards',
  'cunt', 'cunts', 'twat', 'wanker', 'prick', 'dickhead',
  'asshole', 'arsehole', 'dumbass', 'jackass',
  // Censored forms, once the asterisks are stripped: a**hole, sh*t, b*tch, d*ck.
  // "c*nt" is deliberately absent — stripped it becomes "cnt", which an
  // anaesthetist plausibly types for "count" (as in post-tetanic count).
  'ahole', 'sht', 'btch', 'dck',
  'slut', 'sluts', 'whore', 'whores',
  'retard', 'retarded',
  'rapist',
  'scumbag',
  // Roman Urdu / Hindi
  'gandu', 'gaandu', 'gaand',
  'chutiya', 'chutya', 'chutiye', 'chutiyapa',
  'lund', 'lauda', 'lodu',
  'randi', 'gashti', 'kanjar', 'kanjri',
  'harami', 'haramzada', 'haramzadi', 'haramkhor',
  'kamina', 'kamine', 'kaminay', 'kaminey',
  'kutta', 'kutte', 'kutiya', 'kuttiya',
  'bhosda', 'bhosdi', 'bhosdike', 'bhosdiwala',
  'madarchod', 'madrchod', 'maderchod',
  'behenchod', 'bhenchod', 'bahenchod',
  'tharki', 'besharam', 'zaleel', 'badtameez',
];

// Blocked only when NOT clearly self-directed — see design note above.
const MILD = [
  'idiot', 'idiots', 'moron', 'morons', 'imbecile',
  'stupid', 'dumb', 'loser', 'incompetent', 'useless',
  'pagal', 'bewakoof', 'bewaqoof', 'ullu', 'nalayak',
];

// Matched anywhere — these cannot sit inside an innocent word.
const ANY = [
  'motherfuck', 'fuckyou', 'fuckoff', 'stfu',
  'madarchod', 'behenchod', 'bhenchod', 'bhosdike',
  'terimaa', 'teribehen', 'teriman',
];

const SEVERE_SET = new Set([...SEVERE, ...SEVERE.map(collapse)]);
const MILD_SET = new Set([...MILD, ...MILD.map(collapse)]);
const ANY_LIST = [...new Set([...ANY, ...ANY.map(collapse)])];

/** First-person markers near an insult mean the author is talking about
 *  themselves — the case this board exists to encourage. */
const SELF = /\b(?:i|me|my|myself|mine|im|ive|id)\b/;

function isSelfDirected(words, index) {
  // Look back a short window; "I feel stupid", "my stupid mistake".
  const from = Math.max(0, index - 4);
  return words.slice(from, index).some((w) => SELF.test(w));
}

/**
 * @returns {{hit:boolean, severity:'severe'|'mild'|null, terms:string[]}}
 * Matched terms are for the server-side audit log only — never echoed back to
 * the author.
 */
function findAbuse(text) {
  const severe = [];
  const mild = [];

  // Both punctuation readings — see normalise().
  for (const mode of ['split', 'strip']) {
    const collapsed = collapse(despace(normalise(text, mode)));
    const words = collapsed.split(' ').filter(Boolean);

    words.forEach((w, i) => {
      if (SEVERE_SET.has(w)) severe.push(w);
      else if (MILD_SET.has(w) && !isSelfDirected(words, i)) mild.push(w);
    });

    const joined = words.join('');
    for (const a of ANY_LIST) {
      if (joined.includes(a)) severe.push(a);
    }
  }

  const terms = [...new Set([...severe, ...mild])];
  if (!terms.length) return { hit: false, severity: null, terms: [] };
  return { hit: true, severity: severe.length ? 'severe' : 'mild', terms };
}

module.exports = { findAbuse, normalise, collapse, despace, SEVERE, MILD, ANY };
