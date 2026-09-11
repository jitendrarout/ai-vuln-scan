/**
 * AI assistants are very good at generating a correct pattern once, then
 * subtly dropping it on the 3rd or 4th repetition when adapting to a
 * slightly different route. This rule looks for Express-style route
 * definitions in a single file, identifies the middleware name most
 * commonly used across them, and flags routes that omit it — a strong
 * signal of an accidentally-unauthenticated endpoint.
 */

const ROUTE_RE = /\b(app|router)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]\s*,\s*([^)]*)\)/g;

// crude but effective: treat any identifier that looks like a middleware
// function name (not "req"/"res"/"next" and not the final handler-looking
// arrow/function) as a candidate middleware reference.
function extractMiddlewareNames(argsBlob) {
  const names = [];
  const identifierRe = /\b([a-zA-Z_$][\w$]*)\b/g;
  let m;
  while ((m = identifierRe.exec(argsBlob)) !== null) {
    const name = m[1];
    if (['req', 'res', 'next', 'function', 'async'].includes(name)) continue;
    names.push(name);
  }
  return names;
}

function scanAuthConsistency(fileContent, filePath, lang) {
  if (!['js', 'ts'].includes(lang)) return [];

  const routes = [];
  let match;
  ROUTE_RE.lastIndex = 0;
  while ((match = ROUTE_RE.exec(fileContent)) !== null) {
    routes.push({
      method: match[2],
      path: match[3],
      argsBlob: match[4],
      index: match.index,
    });
  }

  if (routes.length < 3) return []; // not enough routes in this file to establish a pattern

  const middlewareCounts = {};
  const routeMiddleware = routes.map((r) => {
    const names = extractMiddlewareNames(r.argsBlob);
    for (const n of names) middlewareCounts[n] = (middlewareCounts[n] || 0) + 1;
    return { ...r, names };
  });

  const candidateAuthNames = Object.entries(middlewareCounts)
    .filter(([name, count]) => count >= Math.ceil(routes.length * 0.5) && /auth|verify|require|protect|guard/i.test(name))
    .map(([name]) => name);

  if (candidateAuthNames.length === 0) return [];

  const findings = [];
  for (const route of routeMiddleware) {
    const hasAuth = candidateAuthNames.some((name) => route.names.includes(name));
    if (!hasAuth) {
      findings.push({
        ruleId: 'inconsistent-auth-middleware',
        category: 'auth-boundary',
        severity: 'critical',
        message: `Route ${route.method.toUpperCase()} ${route.path} does not include ${candidateAuthNames.join('/')}, which is applied to most other routes in this file — possible accidentally-unprotected endpoint.`,
        file: filePath,
        line: lineNumberOf(fileContent, route.index),
        suggestion: `Confirm this route is intentionally public. If not, add the ${candidateAuthNames[0]} middleware used elsewhere in this file.`,
      });
    }
  }
  return findings;
}

function lineNumberOf(content, index) {
  return content.slice(0, index).split('\n').length;
}

module.exports = { scanAuthConsistency };
