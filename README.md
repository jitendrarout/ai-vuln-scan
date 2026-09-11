# ai-vuln-scan

**A static analysis scanner tuned to the specific vulnerability patterns
AI coding assistants tend to introduce** — not a generic linter with
security rules bolted on, but a tool built around a documented taxonomy
of *why* these specific patterns show up in AI-generated code.

See [docs/PATTERN_CATALOG.md](docs/PATTERN_CATALOG.md) for the full,
independently citable taxonomy this scanner is built against.

## What it catches today

| Category | Examples |
|---|---|
| Hardcoded secrets | AWS/Stripe/GitHub key formats, high-entropy secret-like assignments, connection strings with embedded passwords |
| Injection risk | Unparameterized SQL, `eval()`, shell commands built via string interpolation |
| Insecure defaults | CORS wildcards, disabled TLS verification, debug mode left on, weak hashing/randomness for security use |
| Auth boundary bugs | Routes missing auth middleware that's applied to sibling routes in the same file |
| Error leakage | Stack traces / raw error objects returned directly in HTTP responses |

Currently supports JavaScript/TypeScript and Python.

## Install

```bash
git clone https://github.com/jitendrarout/ai-vuln-scan.git
cd ai-vuln-scan
npm install
```

No install-from-registry yet — this is a fresh project. `npm link` locally
if you want the `ai-vuln-scan` command available globally:

```bash
npm link
```

## Usage

```bash
# Scan a directory recursively
ai-vuln-scan scan .

# Scan a single file
ai-vuln-scan scan src/routes/api.js

# Without npm link, run directly:
node bin/ai-vuln-scan.js scan .
```

Try it against the bundled examples:

```bash
npm run scan:examples
```

This scans `examples/vulnerable-samples/`, which contains deliberately
vulnerable JS and Python files demonstrating each pattern in the catalog
— useful both as a demo and as a regression fixture. `examples/clean-sample.js`
is the same routes written safely, to confirm the scanner doesn't produce
false positives on correct code.

**Exit code:** non-zero if any `critical` severity finding is present —
this is what makes it usable as a CI/pre-commit gate.

## Using it as a CI gate

See [.github/workflows/example-action.yml](.github/workflows/example-action.yml)
for a drop-in GitHub Actions workflow that runs the scanner on every PR
and fails the check if critical findings are present.

## Using it as a pre-commit hook

```bash
# .git/hooks/pre-commit
#!/bin/sh
node bin/ai-vuln-scan.js scan $(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(js|ts|py)$')
```

## Why this exists, not just another linter

Existing static analysis tools (ESLint security plugins, Bandit, Semgrep)
catch some of these patterns generically, but none are specifically tuned
to the *distribution* of errors AI coding assistants produce — see
[docs/PATTERN_CATALOG.md](docs/PATTERN_CATALOG.md) for the reasoning
behind each pattern and why it shows up disproportionately in
AI-generated code specifically (not just "a bug that can happen").

## Roadmap

- [ ] AST-based taint analysis (currently regex/structural heuristics —
      works well but will miss some multi-line or aliased patterns)
- [ ] Go, Java, Rust support
- [ ] "Diff-aware" mode: apply stricter thresholds specifically to diffs
      attributable to AI-assisted commits
- [ ] Auto-fix suggestions as applyable patches, not just text suggestions
- [ ] LLM-based second-opinion pass for flagged diffs (logic-level review
      beyond pattern matching)
- [ ] Published labeled dataset of AI-generated vulnerable code samples

Issues and PRs welcome, especially new patterns for
[docs/PATTERN_CATALOG.md](docs/PATTERN_CATALOG.md) — the catalog is
useful independent of whether a detection rule exists yet.

## Disclaimer

This is a pattern-matching and structural-heuristic scanner, not a
complete security audit tool. A clean scan does not mean code is secure;
findings should be reviewed by a human, not auto-trusted or auto-blocked
without judgment for non-critical severities.

## License

MIT — see [LICENSE](LICENSE).
