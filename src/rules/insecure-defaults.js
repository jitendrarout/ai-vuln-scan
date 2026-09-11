/**
 * Detects "works in the demo, unsafe in production" defaults — the class
 * of issue where AI-generated code is functionally correct but ships with
 * the permissive/insecure setting because that's what got past the
 * example prompt, and nobody explicitly asked for the hardened version.
 */

const DEFAULT_PATTERNS = [
  {
    id: 'cors-wildcard',
    label: 'CORS wildcard origin (*)',
    regex: /(Access-Control-Allow-Origin['"]?\s*[:=]\s*['"]\*['"]|cors\(\s*\{\s*origin\s*:\s*['"]\*['"])/gi,
    severity: 'medium',
    langs: ['js', 'ts', 'py'],
    suggestion: 'Restrict CORS to an explicit allowlist of trusted origins instead of *.',
  },
  {
    id: 'tls-verification-disabled-node',
    label: 'TLS certificate verification disabled',
    regex: /(rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0)/g,
    severity: 'critical',
    langs: ['js', 'ts'],
    suggestion: 'Never disable TLS verification outside of local test fixtures — this permits MITM attacks in production.',
  },
  {
    id: 'tls-verification-disabled-python',
    label: 'TLS certificate verification disabled (requests/urllib)',
    regex: /verify\s*=\s*False/g,
    severity: 'critical',
    langs: ['py'],
    suggestion: 'Do not set verify=False outside local testing. Configure a proper CA bundle instead.',
  },
  {
    id: 'debug-mode-flask-django',
    label: 'Debug mode enabled',
    regex: /(app\.run\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True)/g,
    severity: 'high',
    langs: ['py'],
    suggestion: 'Debug mode exposes stack traces and an interactive debugger. Disable it for any non-local deployment.',
  },
  {
    id: 'weak-hash-for-security',
    label: 'Weak hash function (MD5/SHA1) used in a security-relevant context',
    regex: /(md5|sha1)\s*\([^)]*(password|token|secret|auth)/gi,
    severity: 'high',
    langs: ['js', 'ts', 'py'],
    suggestion: 'Use a purpose-built password hash (bcrypt, argon2, scrypt) — MD5/SHA1 are unsuitable for credential storage.',
  },
  {
    id: 'weak-random-for-security',
    label: 'Non-cryptographic random source used for a token/secret',
    // matches either direction: `token = Math.random()...` or `Math.random()...` followed
    // by a token/secret reference within a short window (assistants generate both orderings)
    regex: /((const|let|var)\s+\w*(token|secret|password|session)\w*\s*=\s*(Math\.random\(\)|random\.random\(\))|(Math\.random\(\)|random\.random\(\))[^;\n]{0,40}(token|secret|password|session))/gi,
    severity: 'high',
    langs: ['js', 'ts', 'py'],
    suggestion: 'Use a CSPRNG: crypto.randomBytes()/crypto.getRandomValues() in JS, or secrets module in Python.',
  },
  {
    id: 'stack-trace-in-response',
    label: 'Stack trace or raw error object returned in an HTTP response',
    regex: /(res\.(send|json)\s*\(\s*(err|error)(\.stack)?\s*\)|return\s+jsonify\([^)]*traceback)/gi,
    severity: 'medium',
    langs: ['js', 'ts', 'py'],
    suggestion: 'Log full error details server-side; return a generic error message to the client.',
  },
];

function scanInsecureDefaults(fileContent, filePath, lang) {
  const findings = [];
  for (const pattern of DEFAULT_PATTERNS) {
    if (!pattern.langs.includes(lang)) continue;
    let match;
    pattern.regex.lastIndex = 0;
    while ((match = pattern.regex.exec(fileContent)) !== null) {
      findings.push({
        ruleId: pattern.id,
        category: 'insecure-default',
        severity: pattern.severity,
        message: pattern.label + '.',
        file: filePath,
        line: lineNumberOf(fileContent, match.index),
        suggestion: pattern.suggestion,
      });
    }
  }
  return findings;
}

function lineNumberOf(content, index) {
  return content.slice(0, index).split('\n').length;
}

module.exports = { scanInsecureDefaults };
