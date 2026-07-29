export const meta = {
  name: 'auth-audit',
  description: 'Audit every route handler for missing auth checks, adversarially verified',
  phases: ['Scope', 'Fan out', 'Verify', 'Merge'],
}

// The graph this script builds:
//
//   scope ──┬─> audit r01 ──┐
//           ├─> audit r02 ──┤   (no edges between audits — they never
//           ├─> ...         ├─>  read each other, so they never wait)
//           └─> audit rNN ──┘
//                            └─> verify(finding) x3 lenses ──> merge ──> report
//
// Only the merge is a barrier. Everything above it is independent work.

const FINDING = {
  type: 'object',
  additionalProperties: false,
  properties: {
    file: { type: 'string' },
    line: { type: 'number' },
    handler: { type: 'string' },
    claim: { type: 'string' },
    severity: { type: 'string', enum: ['high', 'medium', 'low'] },
  },
  required: ['file', 'line', 'handler', 'claim', 'severity'],
}

const AUDIT = {
  type: 'object',
  additionalProperties: false,
  properties: { findings: { type: 'array', items: FINDING } },
  required: ['findings'],
}

const VERDICT = {
  type: 'object',
  additionalProperties: false,
  properties: {
    real: { type: 'boolean' },
    reason: { type: 'string' },
  },
  required: ['real', 'reason'],
}

// ---------------------------------------------------------------- 1. scope
phase('Scope')

const scope = await agent(
  `List every route handler file under ${args?.dir ?? 'src/routes/'}. ` +
  `Return repo-relative paths only, no commentary.`,
  {
    label: 'scope',
    schema: {
      type: 'object',
      additionalProperties: false,
      properties: { files: { type: 'array', items: { type: 'string' } } },
      required: ['files'],
    },
  },
)

const files = scope.files.filter(Boolean)
log(`Scoped ${files.length} route files`)

// ------------------------------------------------------------- 2. fan out
// pipeline(), not parallel(): nothing downstream needs the complete set until
// the merge, so a fast file shouldn't queue behind a slow one at a barrier.
phase('Fan out')

const audits = await pipeline(files, (file) =>
  agent(
    `Audit ${file} for route handlers that are missing an authentication or ` +
    `authorization check. For each one, report the handler name, the line, and ` +
    `what specifically is absent. Report nothing if every handler is guarded.`,
    {
      label: file,
      schema: AUDIT,
      // A bounded, repetitive extraction node — no judgment lives here.
      model: 'claude-haiku-4-5-20251001',
    },
  ),
)

// The edge, not a node: flattening is a flatMap, so don't pay an agent for it.
const raw = audits.filter(Boolean).flatMap((a) => a.findings)

// Dedupe against everything SEEN, not everything confirmed — otherwise a
// rejected finding reappears on the next pass forever.
const seen = new Set()
const candidates = raw.filter((f) => {
  const key = `${f.file}:${f.line}:${f.handler}`
  if (seen.has(key)) return false
  seen.add(key)
  return true
})

log(`${raw.length} raw findings → ${candidates.length} unique candidates`)

// -------------------------------------------------------------- 3. verify
// Each finding faces three verifiers with *different* lenses, none of which is
// the agent that authored the finding. Diverse questions catch failure modes
// that three identical checks never will.
phase('Verify')

const LENSES = [
  ['correctness', 'Is the missing check actually absent, or is it applied by a wrapper, middleware, or decorator somewhere up the chain?'],
  ['security', 'If it is absent, is the route genuinely reachable by an unauthenticated caller? Consider route mounting and any gateway-level guard.'],
  ['reproducible', 'Can you point at the exact lines that prove it? Cite them. If you cannot, the finding does not survive.'],
]

const judged = await pipeline(candidates, async (f) => {
  const votes = await parallel(
    LENSES.map(([lens, question]) => () =>
      agent(
        `Try to REFUTE this finding from the ${lens} angle.\n\n` +
        `Finding: ${f.handler} at ${f.file}:${f.line} — ${f.claim}\n\n` +
        `${question}\n\nRead the file before answering. Set real=false if it does not hold up.`,
        { label: `${lens}:${f.file}:${f.line}`, schema: VERDICT },
      ),
    ),
  )
  const survived = votes.filter(Boolean)
  const yes = survived.filter((v) => v.real).length
  // Majority of the votes that actually came back. A finding whose verifiers
  // all errored is unverified, not confirmed.
  return { finding: f, yes, of: survived.length, real: survived.length >= 2 && yes >= 2 }
})

const results = judged.filter(Boolean)
const confirmed = results.filter((r) => r.real).map((r) => r.finding)
const rejected = results.filter((r) => !r.real)

log(`${confirmed.length} confirmed · ${rejected.length} rejected before reporting`)

// --------------------------------------------------------------- 4. merge
// The one real barrier: ranking and grouping needs the whole set at once.
phase('Merge')

if (!confirmed.length) {
  return { confirmed: [], rejected: rejected.length, report: 'No unguarded route handlers survived verification.' }
}

const report = await agent(
  `Write a security report for these verified missing-auth findings. Group by ` +
  `severity, then by file. For each: the handler, the exact location, what is ` +
  `missing, and the concrete fix. Do not soften or pad.\n\n` +
  JSON.stringify(confirmed, null, 2),
  { label: 'merge', schema: { type: 'object', additionalProperties: false, properties: { markdown: { type: 'string' } }, required: ['markdown'] } },
)

return {
  scanned: files.length,
  candidates: candidates.length,
  confirmed: confirmed.length,
  rejected: rejected.length,
  report: report.markdown,
}
