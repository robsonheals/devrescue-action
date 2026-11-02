// DevRescue CI Health Check — GitHub Action entry point.
// Scores the repository's GitHub Actions workflows (cache, concurrency, timeouts, path filters)
// with the DevRescue engine, annotates each finding on the workflow file, writes a job summary
// and optionally fails the job below a minimum score. Runs locally on the runner: nothing is uploaded.
// Generated into dist/index.js by scripts/build-action.ts — edit this template, not the output.

// --- DevRescue Heuristic Engine (generated from lib/engine.ts) ---
// DevRescue Heuristic Engine
// Pure TypeScript, no dependencies and no Node/browser APIs, so the same file runs in
// the API route, in a Web Worker (Offline Mode) and inside the Master Pack CLI.

// Points lost per finding. Each rule counts at most MAX_HITS_PER_RULE times, so one
// noisy rule (e.g. 40 inline styles) can't sink the score on its own.
const PENALTY                           = { critical: 25, high: 10, medium: 4, low: 1 };
const MAX_HITS_PER_RULE = 3;
const MAX_FILE_BYTES = 500_000;

const SEVERITY_ORDER                           = { critical: 0, high: 1, medium: 2, low: 3 };

// ---------------------------------------------------------------------------
// File classification
// ---------------------------------------------------------------------------

const SKIP_FILE = /(^|\/)(node_modules|dist|build|\.next|coverage|vendor)\/|(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?)$|\.min\.(js|css)$|\.(png|jpe?g|gif|svg|ico|webp|woff2?|ttf|pdf|zip|map)$/i;
const CODE_FILE = /\.(m?[jt]sx?|cjs)$/i;
const JSX_FILE = /\.[jt]sx$/i;
const TEST_FILE = /(\.(test|spec)\.|__tests__\/|(^|\/)tests?\/)/i;

function isInline(f            ) {
  return f.path === 'inline';
}

function isWorkflow(f            ) {
  if (/(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i.test(f.path)) return true;
  return isInline(f) && /^\s*jobs:\s*$/m.test(f.content) && /runs-on:/.test(f.content);
}

function isCode(f            ) {
  return isInline(f) || CODE_FILE.test(f.path);
}

function mayHaveJsx(f            ) {
  return JSX_FILE.test(f.path) || (isCode(f) && /<[A-Z][\w.]*[\s>/]|return\s*\(\s*</.test(f.content));
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mask(secret        ) {
  return secret.length <= 6 ? '****' : `${secret.slice(0, 4)}****`;
}

const PLACEHOLDER = /process\.env|import\.meta\.env|\$\{|^<.*>$|your[_-]|example|changeme|placeholder|dummy|xxxx|\*\*\*|test[_-]?(key|secret|token)?$|redacted/i;

// ---------------------------------------------------------------------------
// Line rules (one finding per matching line)
// ---------------------------------------------------------------------------

const anyText = (f            ) => !SKIP_FILE.test(f.path);
const codeOnly = (f            ) => isCode(f) && !SKIP_FILE.test(f.path);
const appCode = (f            ) => codeOnly(f) && !TEST_FILE.test(f.path);

const LINE_RULES             = [
  // --- Security: secrets -----------------------------------------------------
  {
    ruleId: 'secret-aws-key', category: 'security', severity: 'critical', applies: anyText,
    pattern: /\b(AKIA[0-9A-Z]{16})\b/,
    description: 'Hardcoded AWS access key',
    recommendation: 'Revoke this key in AWS IAM now, then load it from an environment variable or a secrets manager.',
    // AKIA...EXAMPLE is the documented sample key in AWS docs, not a real credential
    accept: (m) => !m[1].endsWith('EXAMPLE') && `Hardcoded AWS access key (${mask(m[1])})`,
  },
  {
    ruleId: 'secret-github-token', category: 'security', severity: 'critical', applies: anyText,
    pattern: /\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{22,})\b/,
    description: 'Hardcoded GitHub token',
    recommendation: 'Revoke it in GitHub > Settings > Developer settings, then use a repository secret.',
    accept: (m) => `Hardcoded GitHub token (${mask(m[1])})`,
  },
  {
    ruleId: 'secret-slack-token', category: 'security', severity: 'critical', applies: anyText,
    pattern: /\b(xox[baprs]-[0-9A-Za-z-]{10,})/,
    description: 'Hardcoded Slack token',
    recommendation: 'Rotate the token in the Slack app settings and load it from an environment variable.',
    accept: (m) => `Hardcoded Slack token (${mask(m[1])})`,
  },
  {
    ruleId: 'secret-stripe-live-key', category: 'security', severity: 'critical', applies: anyText,
    pattern: /\b([sr]k_live_[0-9a-zA-Z]{16,})/,
    description: 'Hardcoded Stripe live secret key',
    recommendation: 'Roll the key in the Stripe Dashboard > Developers > API keys and load it from an environment variable.',
    accept: (m) => `Hardcoded Stripe live key (${mask(m[1])})`,
  },
  {
    ruleId: 'secret-private-key', category: 'security', severity: 'critical', applies: anyText,
    pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY( BLOCK)?-----/,
    description: 'Private key committed to the repository',
    recommendation: 'Treat the key as compromised: generate a new one and keep it out of git (add it to .gitignore).',
  },
  {
    // Fuzzy rule: skip tests (fake credentials are normal there) and comment/doc lines.
    ruleId: 'secret-generic', category: 'security', severity: 'high',
    applies: (f) => anyText(f) && !TEST_FILE.test(f.path),
    pattern: /\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b["']?\s*[:=]\s*["']([^"'\s]{8,})["']/i,
    description: 'Possible hardcoded credential',
    recommendation: 'Move the value to an environment variable and rotate it if it was ever pushed.',
    accept: (m, line, inComment) =>
      !PLACEHOLDER.test(m[2]) && !inComment && !/^\s*(\*|\/\/|#|<!--)/.test(line) &&
      `Possible hardcoded ${m[1].toLowerCase()} (${mask(m[2])})`,
  },
  // --- Security: injection / XSS -------------------------------------------
  {
    ruleId: 'sql-injection-template', category: 'security', severity: 'high', applies: appCode,
    pattern: /\b(query|execute|raw|unsafe)\s*\(\s*`[^`]*\b(SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{/i,
    description: 'SQL built with string interpolation',
    recommendation: 'Use parameterized queries ($1, ?) or the query builder of your ORM instead of ${} inside SQL.',
  },
  {
    ruleId: 'sql-injection-concat', category: 'security', severity: 'high', applies: appCode,
    pattern: /["'`]\s*(SELECT|INSERT INTO|UPDATE|DELETE FROM)\b.*["'`]\s*\+\s*[A-Za-z_$][\w.]*/i,
    description: 'SQL built with string concatenation',
    recommendation: 'Use parameterized queries so user input is never concatenated into SQL.',
  },
  {
    ruleId: 'xss-dangerously-set-inner-html', category: 'security', severity: 'medium', applies: appCode,
    pattern: /dangerouslySetInnerHTML\s*=\s*\{/,
    description: 'dangerouslySetInnerHTML renders raw HTML',
    recommendation: 'Sanitize the HTML first (e.g. DOMPurify) or render it as text.',
  },
  {
    ruleId: 'xss-inner-html', category: 'security', severity: 'medium', applies: appCode,
    pattern: /\.(innerHTML|outerHTML)\s*=(?!=)/,
    description: 'Direct innerHTML assignment',
    recommendation: 'Use textContent, or sanitize the HTML before assigning it.',
  },
  {
    ruleId: 'eval-usage', category: 'security', severity: 'high', applies: appCode,
    pattern: /(^|[^\w.])(eval|new Function)\s*\(/,
    description: 'eval / new Function executes arbitrary code',
    recommendation: 'Replace with JSON.parse or an explicit lookup table.',
  },
  // --- Performance -----------------------------------------------------------
  {
    ruleId: 'heavy-import', category: 'performance', severity: 'medium', applies: appCode,
    pattern: /^\s*import\s+(\*\s+as\s+\w+|\w+)\s+from\s+["'](lodash|moment|rxjs|date-fns|@mui\/icons-material|@mui\/material|react-icons|antd)["']/,
    description: 'Whole-library import',
    recommendation: 'Import only what you use (e.g. `import debounce from "lodash/debounce"`), or replace moment with dayjs.',
    accept: (m) => `Whole-library import of "${m[2]}" bloats the bundle`,
  },
  {
    ruleId: 'inline-style-object', category: 'performance', severity: 'low', applies: (f) => appCode(f) && mayHaveJsx(f),
    pattern: /\bstyle=\{\{/,
    description: 'Inline style object recreated on every render',
    recommendation: 'Move static styles to a constant outside the component or to CSS/Tailwind classes.',
  },
  {
    ruleId: 'inline-handler', category: 'performance', severity: 'low', applies: (f) => appCode(f) && mayHaveJsx(f),
    pattern: /\bon[A-Z]\w*=\{\s*(async\s+)?\([^)]*\)\s*=>/,
    description: 'Inline arrow function as event handler',
    recommendation: 'Only matters in long lists or memoized children: wrap the handler in useCallback there.',
  },
];

// ---------------------------------------------------------------------------
// File rules (need more than one line of context)
// ---------------------------------------------------------------------------

function projectContext(files              )                 {
  const pkg = files.find((f) => f.path === 'package.json');
  try {
    const json = pkg ? JSON.parse(pkg.content) : {};
    const pm = typeof json.packageManager === 'string' ? json.packageManager : '';
    const devPm = json.devEngines?.packageManager;
    const devNames = (Array.isArray(devPm) ? devPm : [devPm]).map((p) => p?.name);
    return { npmPackageManager: pm.startsWith('npm@') || devNames.includes('npm') };
  } catch {
    return { npmPackageManager: false };
  }
}

const missingReactKey           = (f, lines) => {
  if (!appCode(f) || !mayHaveJsx(f)) return [];
  const out            = [];
  lines.forEach((line, i) => {
    if (!/\.map\(\s*(\(?[\w\s,{}[\]]*\)?)\s*=>/.test(line)) return;
    // The key belongs on the first JSX element the callback returns: check that tag only.
    // Only callbacks that return JSX: `=> <Tag`, `=> (<Tag` or `=> { ... return <Tag`.
    const window = lines.slice(i, i + 8).join('\n');
    const body = window.slice(window.indexOf('=>') + 2).trimStart();
    const returned = /^\(?\s*</.exec(body) ?? /^\{[\s\S]*?\breturn\s*\(?\s*</.exec(body);
    if (!returned) return;
    const rest = body.slice(returned[0].length - 1);
    const tagEnd = rest.search(/[^=]>/);
    const openingTag = tagEnd < 0 ? rest : rest.slice(0, tagEnd + 2);
    if (!/\bkey=/.test(openingTag)) {
      out.push({
        ruleId: 'react-missing-key', category: 'performance', severity: 'medium',
        file: f.path, line: i + 1,
        description: 'List rendered with .map() without a key prop',
        recommendation: 'Give each item a stable, unique key (an id, not the array index).',
      });
    }
  });
  return out;
};

const workflowRules           = (f, lines, ctx) => {
  if (!isWorkflow(f)) return [];
  const out            = [];
  const text = f.content;
  const lineOf = (re        ) => Math.max(1, lines.findIndex((l) => re.test(l)) + 1);

  // Only judge workflows that run on every push / PR. Release and publish workflows often
  // skip caches on purpose (cache-poisoning hardening), so they are left alone.
  const runsOnEveryChange = /^\s*(pull_request|push)\s*:|on:\s*\[?[^\n]*\b(pull_request|push)\b/m.test(text);
  const releaseLike = /release|publish|deploy|bump|version|tag/i.test(f.path) || /^\s*(release|registry_package)\s*:/m.test(text);

  // Missing dependency cache. Not judged when setup happens in a local composite action or a
  // reusable workflow (we can't see inside it), or when caching was turned off explicitly.
  const install = /\b(npm (ci|install)|yarn( install)?(\s+--?[\w-]+)*\s*$|pnpm install|bun install)\b/m;
  const opaqueSetup = /uses:\s*["']?(\.\/|[\w.-]+\/[\w.-]+\/\.github\/workflows\/)/.test(text);
  const cacheOptOut = /package-manager-cache:\s*false|\bcache:\s*["']?false\b/.test(text);
  const autoNpmCache =
    ctx.npmPackageManager && /actions\/setup-node@v([5-9]|\d{2})\b/.test(text) &&
    /\bnpm (ci|install)\b/.test(text) && !cacheOptOut;
  const hasCache = autoNpmCache || /actions\/cache(\/restore)?@|cache:\s*["']?(npm|yarn|pnpm|true)\b|cache-dependency-path/.test(text);
  if (runsOnEveryChange && !releaseLike && !opaqueSetup && !cacheOptOut && install.test(text) && !hasCache) {
    out.push({
      ruleId: 'ci-missing-cache', category: 'cicd', severity: 'high',
      file: f.path, line: lineOf(install),
      description: 'Dependencies are installed from scratch on every run (no cache)',
      recommendation: 'Add `cache: npm` to actions/setup-node, or an actions/cache step keyed on the lockfile.',
      fix: 'templates/node-ci-cached.yml',
    });
  }

  // Missing concurrency on pull request workflows: every new push to the PR starts another full
  // run while the outdated one keeps going.
  const onPullRequest = /^\s*pull_request\s*:|on:\s*\[?[^\n]*\bpull_request\b/m.test(text);
  if (onPullRequest && !releaseLike && !/^\s*concurrency\s*:/m.test(text)) {
    out.push({
      ruleId: 'ci-missing-concurrency', category: 'cicd', severity: 'medium',
      file: f.path, line: lineOf(/\bpull_request\b/),
      description: 'No concurrency group: outdated PR runs keep going after a new push',
      recommendation: "Add a concurrency group with cancel-in-progress: ${{ github.event_name == 'pull_request' }} to cancel superseded PR runs (pushes to main still finish).",
      fix: 'templates/concurrency-group.yml',
    });
  }

  // Jobs without timeout-minutes (default is 360 minutes)
  const jobsAt = lines.findIndex((l) => /^jobs:\s*$/.test(l));
  if (jobsAt >= 0) {
    const firstJob = lines.slice(jobsAt + 1).find((l) => l.trim() && !l.trim().startsWith('#'));
    const indent = firstJob ? firstJob.length - firstJob.trimStart().length : 2;
    const headers           = [];
    for (let i = jobsAt + 1; i < lines.length; i++) {
      const l = lines[i];
      if (!l.trim() || l.trim().startsWith('#')) continue;
      const ind = l.length - l.trimStart().length;
      if (ind < indent) break; // left the jobs block
      if (ind === indent && /^[\w-]+:\s*$/.test(l.trim())) headers.push(i);
    }
    headers.forEach((start, j) => {
      const block = lines.slice(start, headers[j + 1] ?? lines.length).join('\n');
      if (/runs-on:/.test(block) && !/timeout-minutes:/.test(block)) {
        out.push({
          ruleId: 'ci-missing-timeout', category: 'cicd', severity: 'medium',
          file: f.path, line: start + 1,
          description: `Job "${lines[start].trim().replace(/:$/, '')}" has no timeout-minutes (a hung job can burn 6 hours of CI minutes)`,
          recommendation: 'Set timeout-minutes on every job, around 2x its normal duration.',
          fix: 'templates/node-ci-cached.yml',
        });
      }
    });
  }

  return out;
};

const FILE_RULES             = [missingReactKey, workflowRules];

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

function scoreFindings(findings           ) {
  const hits = new Map                ();
  const lost                                     = { security: 0, performance: 0, cicd: 0, total: 0 };
  for (const f of findings) {
    const n = (hits.get(f.ruleId) ?? 0) + 1;
    hits.set(f.ruleId, n);
    if (n > MAX_HITS_PER_RULE) continue;
    lost[f.category] += PENALTY[f.severity];
    lost.total += PENALTY[f.severity];
  }
  const clamp = (x        ) => Math.max(0, Math.min(100, Math.round(100 - x)));
  return {
    score: clamp(lost.total),
    scores: { security: clamp(lost.security), performance: clamp(lost.performance), cicd: clamp(lost.cicd) },
  };
}

// Marks lines that sit entirely inside a /* ... */ block (JSDoc examples, license headers).
function blockCommentLines(lines          )            {
  let open = false;
  return lines.map((line) => {
    const startedInside = open;
    const lastOpen = line.lastIndexOf('/*');
    const lastClose = line.lastIndexOf('*/');
    if (lastOpen > lastClose) open = true;
    else if (lastClose >= 0) open = false;
    return startedInside && open;
  });
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

function runHeuristicAudit(input                       )              {
  const files = (typeof input === 'string' ? [{ path: 'inline', content: input }] : input).filter(
    (f) => f.content.length <= MAX_FILE_BYTES && !SKIP_FILE.test(f.path),
  );

  const findings            = [];
  const ctx = projectContext(files);
  for (const file of files) {
    const lines = file.content.split(/\r?\n/);
    const rules = LINE_RULES.filter((r) => r.applies(file));
    const commented = isCode(file) ? blockCommentLines(lines) : [];
    lines.forEach((line, i) => {
      for (const rule of rules) {
        const m = rule.pattern.exec(line);
        if (!m) continue;
        const verdict = rule.accept ? rule.accept(m, line, commented[i] ?? false) : true;
        if (verdict === false) continue;
        findings.push({
          ruleId: rule.ruleId,
          category: rule.category,
          severity: rule.severity,
          recommendation: rule.recommendation,
          ...(rule.fix ? { fix: rule.fix } : {}),
          description: typeof verdict === 'string' ? verdict : rule.description,
          file: file.path,
          line: i + 1,
        });
      }
    });
    for (const rule of FILE_RULES) findings.push(...rule(file, lines, ctx));
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.file.localeCompare(b.file) || a.line - b.line);
  const { score, scores } = scoreFindings(findings);
  const count = (s          ) => findings.filter((f) => f.severity === s).length;

  return {
    score,
    scores,
    findings,
    filesScanned: files.length,
    summary: findings.length === 0
      ? `Audit complete. ${files.length} files scanned, no issues found.`
      : `Audit complete. ${files.length} files scanned, ${findings.length} issues found ` +
        `(${count('critical')} critical, ${count('high')} high, ${count('medium')} medium, ${count('low')} low).`,
  };
}

function scoreBand(score        )                             {
  return score >= 80 ? 'green' : score >= 50 ? 'yellow' : 'red';
}

// --- end engine ---

const fs = require('node:fs');
const path = require('node:path');

const SITE = 'https://devrescue.vercel.app';

function input(name, fallback) {
  const v = process.env[`INPUT_${name.toUpperCase()}`];
  return v === undefined || v.trim() === '' ? fallback : v.trim();
}

// Workflow-command escaping (see "Workflow commands for GitHub Actions").
const escData = (s) => String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
const escProp = (s) => escData(s).replace(/:/g, '%3A').replace(/,/g, '%2C');

function append(file, text) {
  if (file) fs.appendFileSync(file, text);
}

function collect(root) {
  const files = [];
  const dir = path.join(root, '.github', 'workflows');
  if (fs.existsSync(dir)) {
    for (const name of fs.readdirSync(dir).sort()) {
      if (!/\.ya?ml$/i.test(name)) continue;
      files.push({ path: `.github/workflows/${name}`, content: fs.readFileSync(path.join(dir, name), 'utf8') });
    }
  }
  const pkg = path.join(root, 'package.json');
  if (fs.existsSync(pkg)) files.push({ path: 'package.json', content: fs.readFileSync(pkg, 'utf8') });
  return files;
}

function main() {
  const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
  const sub = input('path', '.');
  const root = path.resolve(workspace, sub);
  const prefix = path.relative(workspace, root).split(path.sep).join('/');
  const repoPath = (p) => (prefix ? `${prefix}/${p}` : p);
  const minScore = Number(input('min-score', '0'));
  const annotate = input('annotations', 'true') !== 'false';

  const files = collect(root);
  const workflows = files.filter((f) => f.path.startsWith('.github/workflows/')).length;
  if (workflows === 0) {
    console.log(`::notice title=DevRescue::No workflows found in ${escData(repoPath('.github/workflows'))}. Nothing to check.`);
    append(process.env.GITHUB_OUTPUT, 'score=\nfindings=0\n');
    return;
  }

  const result = runHeuristicAudit(files);
  const findings = result.findings.filter((f) => f.category === 'cicd');
  const score = result.scores.cicd;
  const band = scoreBand(score);

  console.log(`DevRescue CI health: ${score}/100 (${findings.length} finding${findings.length === 1 ? '' : 's'} in ${workflows} workflow file${workflows === 1 ? '' : 's'})`);
  for (const f of findings) {
    const level = f.severity === 'low' ? 'notice' : 'warning';
    const msg = `${f.description}. ${f.recommendation}`;
    if (annotate) console.log(`::${level} file=${escProp(repoPath(f.file))},line=${f.line},title=${escProp(`DevRescue: ${f.ruleId}`)}::${escData(msg)}`);
    else console.log(`  [${f.severity}] ${repoPath(f.file)}:${f.line} ${msg}`);
  }

  append(process.env.GITHUB_OUTPUT, `score=${score}\nfindings=${findings.length}\n`);

  const repo = process.env.GITHUB_REPOSITORY;
  const icon = { green: '🟢', yellow: '🟡', red: '🔴' }[band];
  const rows = findings
    .slice(0, 50)
    .map((f) => `| ${f.severity} | \`${repoPath(f.file)}:${f.line}\` | ${f.description.replace(/\|/g, '\\|')} | ${f.recommendation.replace(/\|/g, '\\|')} |`)
    .join('\n');
  append(
    process.env.GITHUB_STEP_SUMMARY,
    [
      `## ${icon} DevRescue CI health: ${score}/100`,
      '',
      findings.length
        ? `| Severity | Where | Problem | Fix |\n|---|---|---|---|\n${rows}${findings.length > 50 ? `\n\n…and ${findings.length - 50} more.` : ''}`
        : 'No problems found in your workflows. 🎉',
      '',
      `Guides for each fix: ${SITE}/guides`,
      repo ? `\nShow it in your README:\n\n\`\`\`md\n[![CI health](${SITE}/badge/${repo})](${SITE}/?repo=${repo})\n\`\`\`` : '',
      '',
    ].join('\n'),
  );

  if (minScore > 0 && score < minScore) {
    console.log(`::error title=DevRescue::CI health ${score}/100 is below the minimum of ${minScore}.`);
    process.exitCode = 1;
  }
}

try {
  main();
} catch (err) {
  console.log(`::error title=DevRescue::${escData(err && err.stack ? err.stack : err)}`);
  process.exitCode = 1;
}
