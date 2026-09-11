/**
 * Detects hardcoded secrets/credentials — one of the most common patterns
 * in AI-generated code, since assistants frequently produce a plausible
 * "example" key that gets left in place rather than swapped for an env var.
 */

const KNOWN_KEY_PATTERNS = [
  { id: 'aws-access-key', label: 'AWS Access Key ID', regex: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
  { id: 'aws-secret-key', label: 'AWS Secret Access Key (heuristic)', regex: /aws(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]/gi, severity: 'critical' },
  { id: 'stripe-key', label: 'Stripe API Key', regex: /sk_(live|test)_[0-9a-zA-Z]{24,}/g, severity: 'critical' },
  { id: 'github-token', label: 'GitHub Token', regex: /gh[pousr]_[0-9a-zA-Z]{36,}/g, severity: 'critical' },
  { id: 'generic-api-key-assignment', label: 'Generic API key/secret assigned as string literal', regex: /(api[_-]?key|secret[_-]?key|access[_-]?token|password)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]/gi, severity: 'high' },
  { id: 'jwt-literal', label: 'JWT-shaped string literal', regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, severity: 'high' },
  { id: 'connection-string-with-password', label: 'Connection string with embedded password', regex: /(postgres|postgresql|mysql|mongodb):\/\/[^:\s]+:[^@\s]+@/gi, severity: 'critical' },
];

function shannonEntropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let entropy = 0;
  for (const ch in freq) {
    const p = freq[ch] / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Catches high-entropy string literals assigned to suspiciously-named
// variables that the known-format regexes above miss (custom/internal
// token formats, for example).
const ENTROPY_ASSIGNMENT_RE = /(secret|token|key|password|credential)\w*\s*[:=]\s*['"]([A-Za-z0-9+/=_\-]{20,})['"]/gi;

function scanSecrets(fileContent, filePath) {
  const findings = [];

  for (const pattern of KNOWN_KEY_PATTERNS) {
    let match;
    pattern.regex.lastIndex = 0;
    while ((match = pattern.regex.exec(fileContent)) !== null) {
      findings.push({
        ruleId: pattern.id,
        category: 'hardcoded-secret',
        severity: pattern.severity,
        message: `Possible ${pattern.label} hardcoded in source.`,
        file: filePath,
        line: lineNumberOf(fileContent, match.index),
        suggestion: 'Move this value to an environment variable or a secrets manager; never commit literal credentials.',
      });
    }
  }

  let entropyMatch;
  ENTROPY_ASSIGNMENT_RE.lastIndex = 0;
  while ((entropyMatch = ENTROPY_ASSIGNMENT_RE.exec(fileContent)) !== null) {
    const value = entropyMatch[2];
    const entropy = shannonEntropy(value);
    if (entropy > 3.5) {
      findings.push({
        ruleId: 'high-entropy-secret-assignment',
        category: 'hardcoded-secret',
        severity: 'medium',
        message: `High-entropy string (entropy ${entropy.toFixed(2)}) assigned to a secret-like variable name — possible hardcoded credential.`,
        file: filePath,
        line: lineNumberOf(fileContent, entropyMatch.index),
        suggestion: 'Verify this is not a real credential. If it is a placeholder, replace with an env var reference before shipping.',
      });
    }
  }

  return findings;
}

function lineNumberOf(content, index) {
  return content.slice(0, index).split('\n').length;
}

module.exports = { scanSecrets, shannonEntropy };
