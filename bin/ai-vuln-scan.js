#!/usr/bin/env node
const path = require('path');
const { scan } = require('../src/scanner');

const SEVERITY_COLOR = {
  critical: '\x1b[41m\x1b[97m CRITICAL \x1b[0m',
  high: '\x1b[31mHIGH\x1b[0m    ',
  medium: '\x1b[33mMEDIUM\x1b[0m  ',
  low: '\x1b[36mLOW\x1b[0m     ',
};

function printReport(result, targetPath) {
  console.log(`\nai-vuln-scan — scanned ${result.filesScanned} file(s) under ${targetPath}\n`);

  if (result.findings.length === 0) {
    console.log('No findings. \u2713\n');
    return;
  }

  for (const f of result.findings) {
    const rel = path.relative(process.cwd(), f.file);
    console.log(`${SEVERITY_COLOR[f.severity] || f.severity}  ${rel}:${f.line}  [${f.ruleId}]`);
    console.log(`   ${f.message}`);
    console.log(`   \u2192 ${f.suggestion}\n`);
  }

  console.log('--- Summary ---');
  console.log(`Total findings: ${result.summary.total}`);
  console.log(
    `By severity: critical=${result.summary.bySeverity.critical} high=${result.summary.bySeverity.high} ` +
    `medium=${result.summary.bySeverity.medium} low=${result.summary.bySeverity.low}`
  );
  console.log('By category:', result.summary.byCategory);
}

function main() {
  const [, , cmd, target] = process.argv;

  if (cmd !== 'scan' || !target) {
    console.log('Usage: ai-vuln-scan scan <file-or-directory>');
    console.log('       ai-vuln-scan scan .              # scan current directory');
    console.log('       ai-vuln-scan scan src/routes.js   # scan a single file');
    process.exit(1);
  }

  const targetPath = path.resolve(process.cwd(), target);
  const result = scan(targetPath);
  printReport(result, target);

  // Exit non-zero if any critical findings — this is what makes it usable
  // as a CI gate.
  if (result.summary.bySeverity.critical > 0) {
    process.exit(1);
  }
}

main();
