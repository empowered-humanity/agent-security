/**
 * JSON Reporter
 *
 * Outputs scan results in JSON format for programmatic consumption.
 */

import type { Finding, ScanResult } from '../patterns/types.js';

/**
 * Serialize a finding to JSON-safe object
 */
function serializeFinding(finding: Finding): object {
  return {
    patternName: finding.pattern.name,
    severity: finding.pattern.severity,
    category: finding.pattern.category,
    description: finding.pattern.description,
    file: finding.file,
    line: finding.line,
    column: finding.column,
    match: finding.match,
    context: finding.context,
    source: finding.pattern.source,
    owaspAsi: finding.pattern.owaspAsi || null,
    cve: finding.pattern.cve || null,
    remediation: finding.pattern.remediation || null,
    timestamp: finding.timestamp.toISOString(),
  };
}

/**
 * Format scan result as JSON string
 */
export function formatAsJson(result: ScanResult, pretty = true): string {
  const output = {
    summary: {
      filesScanned: result.filesScanned,
      patternsChecked: result.patternsChecked,
      totalFindings: result.findings.length,
      duration: result.duration,
      timestamp: result.timestamp.toISOString(),
    },
    riskScore: {
      score: result.riskScore.total,
      level: result.riskScore.level,
      owaspCompliance: result.riskScore.owaspCompliance,
      counts: result.riskScore.counts,
    },
    findings: result.findings.map(serializeFinding),
  };

  return pretty ? JSON.stringify(output, null, 2) : JSON.stringify(output);
}

/**
 * Get findings summary as JSON object
 */
export function getFindingsSummary(result: ScanResult): object {
  const byCategory: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  const byFile: Record<string, number> = {};

  for (const finding of result.findings) {
    byCategory[finding.pattern.category] = (byCategory[finding.pattern.category] || 0) + 1;
    bySeverity[finding.pattern.severity] = (bySeverity[finding.pattern.severity] || 0) + 1;
    byFile[finding.file] = (byFile[finding.file] || 0) + 1;
  }

  return {
    total: result.findings.length,
    byCategory,
    bySeverity,
    byFile,
  };
}

/**
 * Print JSON to console
 */
export function printJson(result: ScanResult, pretty = true): void {
  console.log(formatAsJson(result, pretty));
}
