/**
 * Pattern Matching Engine
 *
 * Core engine for matching security patterns against content.
 * Includes context-aware filtering to reduce false positives
 * by matching pattern context requirements against file types.
 */

import type { DetectionPattern, Finding, MatchContext, RiskScore, ScanResult } from '../patterns/types.js';

/**
 * Contexts that only apply at runtime (agent monitoring), not static file scanning.
 * Patterns with these contexts are skipped during static analysis.
 */
const RUNTIME_ONLY_CONTEXTS: MatchContext[] = [
  'file_write_operation',
  'file_create',
  'outbound_request',
  'email_operation',
  'url_parameter',
  'user_input',
];

/**
 * Map file extensions to their scanning context
 */
const EXT_CONTEXT_MAP: Record<string, MatchContext> = {
  // Config files
  '.json': 'config',
  '.yaml': 'config',
  '.yml': 'config',
  '.toml': 'config',
  '.ini': 'config',
  '.cfg': 'config',
  '.conf': 'config',
  '.xml': 'config',
  // Code files
  '.ts': 'code',
  '.tsx': 'code',
  '.js': 'code',
  '.jsx': 'code',
  '.py': 'code',
  '.go': 'code',
  '.rs': 'code',
  '.java': 'code',
  '.c': 'code',
  '.cpp': 'code',
  '.rb': 'code',
  '.sh': 'code',
  '.bash': 'code',
  '.zsh': 'code',
  '.ps1': 'code',
  // Prompt/text files (where prompt injection is most relevant)
  '.md': 'prompt',
  '.txt': 'prompt',
  '.rst': 'prompt',
};

/**
 * Dependency file patterns for dependency_version context
 */
const DEPENDENCY_FILE_PATTERNS = [
  /package\.json$/i,
  /requirements\.txt$/i,
  /Pipfile$/i,
  /Cargo\.toml$/i,
  /go\.mod$/i,
  /go\.sum$/i,
  /Gemfile$/i,
  /pom\.xml$/i,
  /build\.gradle$/i,
  /\.csproj$/i,
];

/**
 * Infer the scanning context from a file path
 */
export function inferFileContext(filePath: string): MatchContext {
  const lower = filePath.toLowerCase().replace(/\\/g, '/');

  // Check for .env files (any .env variant)
  if (/\.env(?:\.\w+)?$/.test(lower)) return 'config';

  // Check for dependency files
  for (const depPattern of DEPENDENCY_FILE_PATTERNS) {
    if (depPattern.test(lower)) return 'dependency_version';
  }

  // Check extension
  const ext = lower.match(/\.[^./\\]+$/)?.[0] || '';
  return EXT_CONTEXT_MAP[ext] || 'any';
}

/**
 * Determine if a pattern should be applied to a given file during static scanning.
 * Filters out runtime-only patterns and mismatched context/file combinations.
 */
export function shouldApplyPattern(pattern: DetectionPattern, filePath: string): boolean {
  const patternContext = pattern.context;

  // No context or 'any' → always apply
  if (!patternContext || patternContext === 'any') return true;

  // Runtime-only contexts → skip in static scanning
  if (RUNTIME_ONLY_CONTEXTS.includes(patternContext)) return false;

  const fileContext = inferFileContext(filePath);

  // Unknown file type → apply the pattern (be conservative)
  if (fileContext === 'any') return true;

  // dependency_version patterns only match dependency files
  if (patternContext === 'dependency_version') {
    return fileContext === 'dependency_version';
  }

  // generated_code and command_template match code files
  if (patternContext === 'generated_code' || patternContext === 'command_template') {
    return fileContext === 'code';
  }

  // config patterns match config and dependency files
  if (patternContext === 'config') {
    return fileContext === 'config' || fileContext === 'dependency_version';
  }

  // code patterns match code files only
  if (patternContext === 'code') return fileContext === 'code';

  // prompt patterns match prompt/text files only
  if (patternContext === 'prompt') return fileContext === 'prompt';

  return true;
}

/**
 * Match a single pattern against content
 */
export function matchPattern(
  pattern: DetectionPattern,
  content: string,
  file: string
): Finding[] {
  // Context-aware filtering: skip patterns that don't apply to this file type
  if (!shouldApplyPattern(pattern, file)) return [];

  const findings: Finding[] = [];
  const lines = content.split('\n');

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex];
    const matches = line.matchAll(new RegExp(pattern.pattern, 'gi'));

    for (const match of matches) {
      findings.push({
        pattern,
        file,
        line: lineIndex + 1,
        column: (match.index || 0) + 1,
        match: match[0],
        context: getContext(lines, lineIndex),
        timestamp: new Date(),
      });
    }
  }

  return findings;
}

/**
 * Get surrounding context for a line
 */
function getContext(lines: string[], lineIndex: number, contextSize = 2): string {
  const start = Math.max(0, lineIndex - contextSize);
  const end = Math.min(lines.length, lineIndex + contextSize + 1);
  return lines.slice(start, end).join('\n');
}

/**
 * Match multiple patterns against content
 */
export function matchPatterns(
  patterns: DetectionPattern[],
  content: string,
  file: string
): Finding[] {
  const findings: Finding[] = [];

  for (const pattern of patterns) {
    findings.push(...matchPattern(pattern, content, file));
  }

  return findings;
}

/**
 * Calculate risk score from findings
 */
export function calculateRiskScore(findings: Finding[]): RiskScore {
  const weights = {
    critical: 25,
    high: 10,
    medium: 3,
    low: 1,
  };

  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  let deductions = 0;

  for (const finding of findings) {
    counts[finding.pattern.severity]++;
    deductions += weights[finding.pattern.severity];
  }

  const total = Math.max(0, 100 - deductions);

  let level: RiskScore['level'];
  if (total >= 80) level = 'low';
  else if (total >= 60) level = 'moderate';
  else if (total >= 40) level = 'high';
  else level = 'critical';

  // Calculate OWASP ASI compliance (simplified)
  const owaspFindings = findings.filter((f) => f.pattern.owaspAsi);
  const owaspCompliance = owaspFindings.length === 0 ? 100 : Math.max(0, 100 - owaspFindings.length * 10);

  return {
    total,
    level,
    counts,
    owaspCompliance,
  };
}

/**
 * Deduplicate findings (same pattern, same location)
 */
export function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.pattern.name}:${f.file}:${f.line}:${f.column}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Sort findings by severity (critical first)
 */
export function sortFindingsBySeverity(findings: Finding[]): Finding[] {
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  return [...findings].sort(
    (a, b) => severityOrder[a.pattern.severity] - severityOrder[b.pattern.severity]
  );
}

/**
 * Group findings by file
 */
export function groupFindingsByFile(findings: Finding[]): Map<string, Finding[]> {
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    const existing = groups.get(finding.file) || [];
    existing.push(finding);
    groups.set(finding.file, existing);
  }
  return groups;
}

/**
 * Group findings by category
 */
export function groupFindingsByCategory(findings: Finding[]): Map<string, Finding[]> {
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    const category = finding.pattern.category;
    const existing = groups.get(category) || [];
    existing.push(finding);
    groups.set(category, existing);
  }
  return groups;
}

/**
 * Filter findings by minimum severity
 */
export function filterFindingsBySeverity(
  findings: Finding[],
  minSeverity: 'critical' | 'high' | 'medium' | 'low'
): Finding[] {
  const severityOrder = { low: 0, medium: 1, high: 2, critical: 3 };
  const minLevel = severityOrder[minSeverity];
  return findings.filter((f) => severityOrder[f.pattern.severity] >= minLevel);
}

/**
 * Create a scan result object
 */
export function createScanResult(
  filesScanned: number,
  patternsChecked: number,
  findings: Finding[],
  startTime: number
): ScanResult {
  return {
    filesScanned,
    patternsChecked,
    findings: sortFindingsBySeverity(deduplicateFindings(findings)),
    riskScore: calculateRiskScore(findings),
    duration: Date.now() - startTime,
    timestamp: new Date(),
  };
}
