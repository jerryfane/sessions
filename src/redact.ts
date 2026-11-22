/**
 * Secret redaction for text the index stores from tool output. Tool output carries
 * credentials far more often than conversation does (a `cat .env`, a `curl -H
 * 'Authorization: …'`, a printed config), and the index would otherwise copy them into
 * a searchable table and into search hits.
 *
 * Each match is replaced by `[REDACTED:<kind>]`; callers keep only the counts.
 */

const RULES: readonly (readonly [string, RegExp])[] = [
  ['private_key', /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g],
  ['jwt', /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g],
  [
    'auth_header',
    /\b(?:authorization|proxy-authorization|x-api-key|api-key|x-auth-token)\s*[:=]\s*(?:"[^"\n]*"|'[^'\n]*'|(?:bearer|basic|token)\s+\S+|\S+)/gi,
  ],
  ['bearer', /\bbearer\s+[A-Za-z0-9._~+/=-]{12,}/gi],
  ['cookie', /\b(?:set-cookie|cookie)\s*:\s*[^\n]*/gi],
  ['connection_string', /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@"'<>]+:[^\s@"'<>]+@[^\s"'<>]+/gi],
  ['github_token', /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})/g],
  ['api_key', /\b(?:sk|rk|pk)-(?:proj-|ant-|or-v1-|live_|test_)?[A-Za-z0-9_-]{20,}/g],
  ['slack_token', /\bxox[abeprs]-[A-Za-z0-9-]{10,}/g],
  ['aws_key', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g],
  ['google_key', /\bAIza[0-9A-Za-z_-]{30,}/g],
  ['telegram_bot_token', /\b\d{8,10}:AA[0-9A-Za-z_-]{30,}/g],
  ['password', /\b(?:password|passwd|pwd|passphrase)\b\s*[:=]\s*(?:"[^"\n]*"|'[^'\n]*'|\S+)/gi],
  [
    'secret_assignment',
    /\b[A-Z0-9_]*(?:TOKEN|SECRET|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|CLIENT_SECRET)[A-Z0-9_]*\s*[:=]\s*(?:"[^"\n]*"|'[^'\n]*'|\S+)/g,
  ],
  [
    'json_secret',
    /"(?:token|access_token|refresh_token|id_token|secret|client_secret|api_key|apikey|password|private_key)"\s*:\s*"[^"]*"/gi,
  ],
  ['url_secret', /([?&](?:token|access_token|key|api_key|apikey|secret|sig|signature|password)=)[^&\s"'<>]+/gi],
];

export type RedactionCounts = Record<string, number>;

/** `text` with every secret replaced by `[REDACTED:<kind>]`; matches are counted into `counts`. */
export function redactSecrets(text: string, counts: RedactionCounts): string {
  let out = text;
  for (const [kind, re] of RULES) {
    out = out.replace(re, () => {
      counts[kind] = (counts[kind] ?? 0) + 1;
      return `[REDACTED:${kind}]`;
    });
  }
  return out;
}
