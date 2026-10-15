// Redactarea datelor sensibile din URL-uri înainte de stocare/afișare/export.
const SENSITIVE_PARAM = /(^|[_-])(token|access[_-]?token|id[_-]?token|refresh[_-]?token|auth|authorization|password|passwd|pass|pwd|secret|key|api[_-]?key|apikey|session|sessionid|sid|code|otp|pin|signature|sig|jwt|bearer|ticket|csrf|xsrf|sso|credential|cred|private|email|mail|phone|ssn|iban|card)([_-]|$)/i;
const JWT_LIKE = /^eyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]*$/;
const TOKEN_LIKE = /^[A-Za-z0-9+/_=-]{24,}$/;
const HEX_LIKE = /^[a-f0-9]{24,}$/i;

export function looksLikeSecretValue(v) {
  return JWT_LIKE.test(v) || HEX_LIKE.test(v) || (TOKEN_LIKE.test(v) && /\d/.test(v) && /[A-Za-z]/.test(v));
}

/**
 * @param {string} url
 * @param {'redact-sensitive'|'strip-query'|'host-only'|'full'} mode
 * Credențialele din autoritate (user:parolă@) sunt eliminate ÎNTOTDEAUNA, chiar și în modul `full`.
 */
export function redactUrl(url, mode = 'redact-sensitive') {
  let u;
  try { u = new URL(url); } catch { return String(url).slice(0, 200).replace(/[?#].*$/, ''); }
  if (!/^https?:$/.test(u.protocol)) return u.protocol + '(…)';
  u.username = '';
  u.password = '';
  if (mode === 'host-only') return `${u.protocol}//${u.host}/`;
  if (mode === 'strip-query') { u.search = ''; u.hash = ''; return u.href; }
  if (mode === 'full') return u.href;
  const clean = new URLSearchParams();
  for (const [k, v] of u.searchParams) {
    clean.append(k, SENSITIVE_PARAM.test(k) || looksLikeSecretValue(v) ? '[redactat]' : v.slice(0, 200));
  }
  u.search = clean.toString();
  u.hash = ''; // fragmentul poate conține tokenuri (flux OAuth implicit)
  return u.href.replace(/%5Bredactat%5D/g, '[redactat]');
}

/** Dacă URL-ul pare să conțină secrete (folosit pentru a nu trimite niciodată astfel de URL-uri către servicii externe). */
export function containsSensitiveData(url) {
  let u;
  try { u = new URL(url); } catch { return false; }
  if (u.username || u.password) return true;
  for (const [k, v] of u.searchParams) if (SENSITIVE_PARAM.test(k) || looksLikeSecretValue(v)) return true;
  if (u.pathname.split('/').some((seg) => JWT_LIKE.test(seg) || HEX_LIKE.test(seg))) return true;
  return u.hash.length > 1 && /(token|access|code|id_token)=/i.test(u.hash);
}

/** Text sigur pentru afișare (limitează lungimea, elimină caractere de control și bidi). */
export function safeText(s, max = 300) {
  return String(s ?? '').replace(/[\u0000-\u001f\u007f​-‏‪-‮⁦-⁩]/g, '').slice(0, max);
}
