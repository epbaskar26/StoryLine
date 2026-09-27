// Privacy boundary for the AI case summary (Extended Spec section 7):
// tokenize every entity name, scrub free text, re-hydrate the answer, and audit its citations.
import type { UserProfile, NodeType, CitationAudit } from '../src/types';

const TOKEN_PREFIX: Record<NodeType, string> = {
  user: 'USER', host: 'HOST', ip: 'IP', application: 'APP', file: 'FILE', process: 'PROC', domain: 'DOMAIN', alert: 'ALERT',
};

export interface TokenizedContext {
  payload: Record<string, unknown>;
  tokenByNodeId: Record<string, string>;
  nameByToken: Record<string, string>;
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Replace every known entity string with its token, then catch remaining IPs, emails, and DOMAIN\user forms.
export function scrubText(text: string, replacements: [string, string][]): string {
  let out = text;
  const sorted = [...replacements].filter(([s]) => s && s.length >= 3).sort((a, b) => b[0].length - a[0].length);
  for (const [raw, token] of sorted) {
    out = out.replace(new RegExp(escapeRegex(raw), 'gi'), token);
  }
  out = out
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, 'IP_REDACTED')
    .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, 'EMAIL_REDACTED')
    .replace(/\b[A-Za-z0-9_-]+\\[A-Za-z0-9._$-]+/g, 'ACCOUNT_REDACTED')
    .replace(/[A-Za-z]:\\[^\s,;)]+/g, 'PATH_REDACTED');
  return out;
}

export function tokenizeProfile(profile: UserProfile, privacyMode: boolean): TokenizedContext {
  const counters: Partial<Record<NodeType, number>> = {};
  const tokenByNodeId: Record<string, string> = {};
  const nameByToken: Record<string, string> = {};
  const replacements: [string, string][] = [];

  const rootId =
    profile.nodes.find(n => n.type === 'user' && n.name.toLowerCase() === profile.username.toLowerCase())?.id ??
    profile.nodes.find(n => n.type === 'user')?.id;
  const orderedNodes = [...profile.nodes].sort((a, b) => (a.id === rootId ? -1 : b.id === rootId ? 1 : 0));

  for (const n of orderedNodes) {
    const c = (counters[n.type] = (counters[n.type] || 0) + 1);
    const token = `${TOKEN_PREFIX[n.type]}_${c}`;
    tokenByNodeId[n.id] = token;
    nameByToken[token] = n.name;
    replacements.push([n.name, token]);
    (n.aliases || []).forEach(a => replacements.push([a, token]));
    // Also match fragments of the name as they appear in free text: "SRV-HR-DB01.corp (Payroll_SSN)"
    // should catch "SRV-HR-DB01.corp", "SRV-HR-DB01" and "Payroll_SSN".
    for (const part of n.name.split(/[\s()@,;]+/)) {
      if (part.length >= 5 && /[0-9._\-]/.test(part) && /[A-Za-z]/.test(part)) {
        replacements.push([part, token]);
        const firstLabel = part.split('.')[0];
        if (firstLabel !== part && firstLabel.length >= 5 && /[0-9-]/.test(firstLabel)) replacements.push([firstLabel, token]);
      }
    }
    // Values such as hostnames and paths in node details also identify the entity
    for (const v of Object.values(n.details || {})) {
      if (typeof v === 'string' && v.length >= 3 && v.length <= 200 && /[A-Za-z0-9]/.test(v) && !/\s{2,}/.test(v)) {
        if (/[.\\/:_-]/.test(v) || /^[A-Z0-9-]{4,}$/.test(v)) replacements.push([v, token]);
      }
    }
  }
  replacements.push([profile.username, tokenByNodeId[rootId || ''] || 'USER_1']);
  profile.aliases.forEach(a => replacements.push([a, tokenByNodeId[rootId || ''] || 'USER_1']));
  if (profile.fullName && profile.fullName !== profile.username) replacements.push([profile.fullName, tokenByNodeId[rootId || ''] || 'USER_1']);

  const name = (id: string) => (privacyMode ? tokenByNodeId[id] || 'ENTITY' : profile.nodes.find(n => n.id === id)?.name || id);
  const text = (s: string) => (privacyMode ? scrubText(s, replacements) : s);

  const nodeById = new Map(profile.nodes.map(n => [n.id, n]));
  const graphFacts = [...profile.edges]
    .sort((a, b) => b.hour - a.hour)
    .slice(0, 300)
    .map(e => {
      const tgt = nodeById.get(e.target);
      const attrs = [
        e.firstSeenInBaseline === false ? 'first_seen' : '',
        tgt?.isCrownJewel ? 'crown_jewel' : '',
        e.status !== 'allowed' ? e.status : '',
      ].filter(Boolean);
      return {
        id: e.id,
        t: `T-${String(e.hour).padStart(2, '0')}:00`,
        fact: `${name(e.source)} ${e.type} ${name(e.target)}${attrs.length ? ` (${attrs.join(', ')})` : ''}`,
        protocol: privacyMode ? text(e.protocol) : e.protocol,
        count: e.eventCount,
        ttp: e.ttp || [],
      };
    });

  const entities = profile.nodes.map(n => ({
    id: n.id,
    token: name(n.id),
    type: n.type,
    riskBand: n.riskBand,
    highRisk: n.compromised,
    crownJewel: !!n.isCrownJewel,
  }));

  const payload = {
    investigation_context: {
      entity: rootId ? name(rootId) : privacyMode ? 'USER_1' : profile.username,
      entity_node_id: rootId,
      role: privacyMode ? text(profile.role) : profile.role,
      department: privacyMode ? text(profile.department) : profile.department,
      risk_score: profile.riskScore,
      risk_band: profile.riskBand,
      window_hours: profile.windowHours ?? 48,
      baseline_available: profile.baselineAvailable ?? true,
    },
    contributing_factors: profile.contributingFactors.map(f => ({
      indicator: f.indicator,
      weight: f.weight,
      mitre: f.mitreTactic,
      edge_ids: f.edgeIds || [],
      description: text(f.description),
    })),
    graph_facts: graphFacts,
    entities,
  };

  return { payload, tokenByNodeId, nameByToken };
}

// Replace tokens in the model output with the real names (done server-side, after the model call).
export function rehydrate(text: string, nameByToken: Record<string, string>): string {
  const tokens = Object.keys(nameByToken).sort((a, b) => b.length - a.length);
  if (!tokens.length) return text;
  const re = new RegExp(`\\b(${tokens.map(escapeRegex).join('|')})\\b`, 'g');
  return text.replace(re, t => nameByToken[t] || t);
}

// Check every [citation] against real node/edge ids, and count timeline/blast-radius lines with none.
export function auditCitations(summary: string, profile: UserProfile): CitationAudit {
  const ids = new Set([...profile.nodes.map(n => n.id), ...profile.edges.map(e => e.id)]);
  const cites = Array.from(summary.matchAll(/\[([a-zA-Z0-9_\-]+)\]/g)).map(m => m[1]);
  const invalid = Array.from(new Set(cites.filter(c => !ids.has(c) && !/^T\d{4}/.test(c))));
  let uncited = 0;
  let inCheckedSection = false;
  for (const line of summary.split('\n')) {
    if (/^#{1,6}\s/.test(line)) {
      inCheckedSection = /timeline|blast radius/i.test(line);
      continue;
    }
    if (inCheckedSection && /^\s*(-|\*|\d+\.)\s+\S/.test(line) && !/\[[a-zA-Z0-9_\-]+\]/.test(line)) uncited++;
  }
  return {
    totalCitations: cites.length,
    validCitations: cites.filter(c => ids.has(c)).length,
    invalidCitations: invalid,
    uncitedLines: uncited,
  };
}

// Deterministic summary built only from the graph, used when no AI key is configured or the model call fails.
export function deterministicSummary(profile: UserProfile): string {
  const root = profile.nodes.find(n => n.type === 'user' && n.name === profile.username) || profile.nodes[0];
  const rootCite = root ? ` [${root.id}]` : '';
  const factors = [...profile.contributingFactors].sort((a, b) => b.weight - a.weight);
  const risky = profile.edges.filter(e => e.status === 'critical' || e.status === 'anomalous').sort((a, b) => b.hour - a.hour);
  const nodeName = (id: string) => profile.nodes.find(n => n.id === id)?.name || id;
  const verdict = profile.riskBand === 'HIGH' ? 'Likely malicious' : profile.riskBand === 'MEDIUM' ? 'Suspicious' : 'Likely benign';

  const headline = factors.length
    ? `${profile.username}${rootCite} scored ${profile.riskScore}/100 (${profile.riskBand}) over the last ${profile.windowHours ?? 48} h, driven by ${factors.slice(0, 3).map(f => f.indicator.toLowerCase()).join(', ')}${factors[0].edgeIds?.length ? ` [${factors[0].edgeIds[0]}]` : ''}.`
    : `${profile.username}${rootCite} scored ${profile.riskScore}/100 (${profile.riskBand}); no risk indicators fired in the last ${profile.windowHours ?? 48} h.`;

  const timeline = (risky.length ? risky : [...profile.edges].sort((a, b) => b.hour - a.hour)).slice(0, 10).map(e =>
    `- **T-${String(e.hour).padStart(2, '0')}:00:** ${nodeName(e.source)} ${e.type} ${nodeName(e.target)} (${e.eventCount} event(s), ${e.status}) [${e.id}]`,
  );

  const crown = profile.nodes.filter(n => n.isCrownJewel);
  const highRisk = profile.nodes.filter(n => n.compromised && n.id !== root?.id);
  const blast = [
    `- **Root identity:** ${profile.username}${rootCite}`,
    ...(highRisk.length ? [`- **High-risk entities:** ${highRisk.slice(0, 8).map(n => `${n.name} [${n.id}]`).join(', ')}`] : []),
    ...(crown.length ? [`- **Crown jewels touched:** ${crown.map(n => `${n.name} [${n.id}]`).join(', ')}`] : []),
  ];

  const ttps = Array.from(new Set(factors.map(f => f.mitreTactic).filter(t => /^T\d/.test(t))));

  return [
    `# WATCHME CASE SUMMARY: ${profile.triggerEvent}`,
    '',
    '### 1. Headline',
    headline,
    '',
    '### 2. Timeline',
    ...(timeline.length ? timeline : ['- No activity in the window.']),
    '',
    '### 3. Blast Radius',
    ...blast,
    '',
    '### 4. ATT&CK Mapping',
    ...(ttps.length ? ttps.map(t => `- ${t}: ${factors.filter(f => f.mitreTactic === t).map(f => f.indicator).join(', ')}`) : ['- No techniques mapped.']),
    '',
    '### 5. Assessment',
    `- **${verdict}** (risk ${profile.riskScore}/100). Based on: ${factors.length ? factors.map(f => `${f.indicator} (+${f.weight})`).join(', ') : 'no fired indicators'}.`,
    '- Generated without an AI model from graph facts only. Confidence reflects the indicator weights, not a model estimate.',
    '',
    '### 6. Recommended Next Steps',
    '1. Validate the highest-weight indicator with the source logs (use the event IDs on the cited edges).',
    '2. Confirm with the user or their manager whether the first-seen access was expected.',
    ...(profile.riskBand === 'HIGH' ? ['3. If not expected: reset credentials, revoke sessions, and isolate the hosts listed under high-risk entities.'] : []),
  ].join('\n');
}
