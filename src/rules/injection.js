/**
 * Detects the "happy path" injection risk pattern AI assistants commonly
 * generate: building a query, shell command, or eval'd string via direct
 * concatenation/template-literal interpolation of a variable, instead of
 * using parameterized queries or safe APIs.
 */

const DANGEROUS_PATTERNS = [
  {
    id: 'js-eval-usage',
    label: 'Use of eval()',
    regex: /\beval\s*\(/g,
    severity: 'high',
    langs: ['js', 'ts'],
    suggestion: 'Avoid eval(). If dynamic execution is truly required, use a sandboxed evaluator with a strict allowlist.',
  },
  {
    id: 'js-child-process-exec-interpolated',
    label: 'child_process.exec() with interpolated string',
    regex: /(exec|execSync)\s*\(\s*(`[^`]*\$\{[^}]+\}[^`]*`|[a-zA-Z_$][\w$]*\s*\+)/g,
    severity: 'critical',
    langs: ['js', 'ts'],
    suggestion: 'Use execFile()/spawn() with an argument array instead of a shell string, so user input cannot break out of the intended command.',
  },
  {
    id: 'js-sql-template-literal',
    label: 'SQL-looking template literal with interpolation',
    regex: /(query|execute)\s*\(\s*`[^`]*(SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{[^}]+\}[^`]*`/gis,
    severity: 'critical',
    langs: ['js', 'ts'],
    suggestion: 'Use parameterized queries (?, $1, or a query builder) instead of interpolating variables directly into SQL.',
  },
  {
    id: 'py-os-system',
    label: 'os.system() call',
    regex: /os\.system\s*\(/g,
    severity: 'high',
    langs: ['py'],
    suggestion: 'Use subprocess.run() with a list of arguments and shell=False instead of os.system().',
  },
  {
    id: 'py-subprocess-shell-true',
    label: 'subprocess call with shell=True',
    regex: /subprocess\.(run|call|Popen)\([^)]*shell\s*=\s*True/gs,
    severity: 'critical',
    langs: ['py'],
    suggestion: 'Avoid shell=True with any user-influenced input. Pass command and args as a list instead.',
  },
  {
    id: 'py-fstring-sql',
    label: 'f-string used to build a SQL statement',
    regex: /(execute|executemany)\s*\(\s*f['"][^'"]*(SELECT|INSERT|UPDATE|DELETE)/gi,
    severity: 'critical',
    langs: ['py'],
    suggestion: 'Use parameterized queries (cursor.execute(query, params)) instead of an f-string to build SQL.',
  },
];

function scanInjectionRisk(fileContent, filePath, lang) {
  const findings = [];
  for (const pattern of DANGEROUS_PATTERNS) {
    if (!pattern.langs.includes(lang)) continue;
    let match;
    pattern.regex.lastIndex = 0;
    while ((match = pattern.regex.exec(fileContent)) !== null) {
      findings.push({
        ruleId: pattern.id,
        category: 'injection-risk',
        severity: pattern.severity,
        message: pattern.label + ' — verify no untrusted input reaches this call unsanitized.',
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

module.exports = { scanInjectionRisk };
