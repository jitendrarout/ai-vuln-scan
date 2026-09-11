const fs = require('fs');
const path = require('path');

const { scanSecrets } = require('./rules/secrets');
const { scanInjectionRisk } = require('./rules/injection');
const { scanInsecureDefaults } = require('./rules/insecure-defaults');
const { scanAuthConsistency } = require('./rules/auth-consistency');

const EXT_TO_LANG = { '.js': 'js', '.jsx': 'js', '.ts': 'ts', '.tsx': 'ts', '.py': 'py' };
const DEFAULT_IGNORE_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '__pycache__', '.venv', 'venv']);

function walk(dir, fileList = []) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (DEFAULT_IGNORE_DIRS.has(entry.name)) continue;
      walk(path.join(dir, entry.name), fileList);
    } else {
      const ext = path.extname(entry.name);
      if (EXT_TO_LANG[ext]) fileList.push(path.join(dir, entry.name));
    }
  }
  return fileList;
}

function scanFile(filePath) {
  const ext = path.extname(filePath);
  const lang = EXT_TO_LANG[ext];
  if (!lang) return [];

  const content = fs.readFileSync(filePath, 'utf8');
  const findings = [
    ...scanSecrets(content, filePath),
    ...scanInjectionRisk(content, filePath, lang),
    ...scanInsecureDefaults(content, filePath, lang),
    ...scanAuthConsistency(content, filePath, lang),
  ];
  return findings;
}

/**
 * Scans a single file or a directory (recursively) and returns all findings,
 * sorted by severity (critical first) then by file/line.
 */
function scan(targetPath) {
  const stat = fs.statSync(targetPath);
  const files = stat.isDirectory() ? walk(targetPath) : [targetPath];

  let findings = [];
  for (const file of files) {
    findings = findings.concat(scanFile(file));
  }

  const severityRank = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => {
    const sevDiff = severityRank[a.severity] - severityRank[b.severity];
    if (sevDiff !== 0) return sevDiff;
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    return a.line - b.line;
  });

  return {
    filesScanned: files.length,
    findings,
    summary: summarize(findings),
  };
}

function summarize(findings) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  const byCategory = {};
  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    byCategory[f.category] = (byCategory[f.category] || 0) + 1;
  }
  return { total: findings.length, bySeverity, byCategory };
}

module.exports = { scan, scanFile, walk };
