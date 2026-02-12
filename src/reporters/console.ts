/**
 * Console Reporter
 *
 * Formats scan results for terminal output with colors.
 */

import chalk from 'chalk';
import type { Finding, ScanResult, Severity } from '../patterns/types.js';
import { groupFindingsByFile, groupFindingsByCategory } from '../scanner/engine.js';

const SEVERITY_COLORS: Record<Severity, (text: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow,
  low: chalk.blue,
};

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: '🚨',
  high: '❌',
  medium: '⚠️',
  low: 'ℹ️',
};

/**
 * Format a single finding for console output
 */
export function formatFinding(finding: Finding, showContext = false): string {
  const { pattern, file, line, column, match } = finding;
  const severityColor = SEVERITY_COLORS[pattern.severity];
  const icon = SEVERITY_ICONS[pattern.severity];

  let output = `${icon} ${severityColor(`[${pattern.severity.toUpperCase()}]`)} ${chalk.cyan(pattern.name)}\n`;
  output += `   ${chalk.gray('File:')} ${file}:${line}:${column}\n`;
  output += `   ${chalk.gray('Match:')} ${chalk.white(match)}\n`;
  output += `   ${chalk.gray('Description:')} ${pattern.description}\n`;

  if (pattern.owaspAsi) {
    output += `   ${chalk.gray('OWASP ASI:')} ${chalk.magenta(pattern.owaspAsi)}\n`;
  }

  if (pattern.cve) {
    output += `   ${chalk.gray('CVE:')} ${chalk.red(pattern.cve)}\n`;
  }

  if (pattern.remediation) {
    output += `   ${chalk.gray('Remediation:')} ${chalk.green(pattern.remediation)}\n`;
  }

  if (showContext && finding.context) {
    output += `   ${chalk.gray('Context:')}\n`;
    const lines = finding.context.split('\n');
    for (const contextLine of lines) {
      output += `   ${chalk.dim('│')} ${contextLine}\n`;
    }
  }

  return output;
}

/**
 * Format the risk score for console output
 */
export function formatRiskScore(result: ScanResult): string {
  const { riskScore } = result;
  let levelColor: (text: string) => string;

  switch (riskScore.level) {
    case 'critical':
      levelColor = chalk.bgRed.white.bold;
      break;
    case 'high':
      levelColor = chalk.red.bold;
      break;
    case 'moderate':
      levelColor = chalk.yellow.bold;
      break;
    case 'low':
      levelColor = chalk.green.bold;
      break;
  }

  let output = chalk.bold('\n📊 Risk Assessment\n');
  output += `${chalk.gray('═'.repeat(40))}\n`;
  output += `Risk Score: ${levelColor(`${riskScore.total}/100`)} (${levelColor(riskScore.level.toUpperCase())})\n`;
  output += `OWASP Compliance: ${riskScore.owaspCompliance >= 80 ? chalk.green : chalk.red}(${riskScore.owaspCompliance}%)\n\n`;

  output += chalk.bold('Findings by Severity:\n');
  output += `  ${SEVERITY_ICONS.critical} Critical: ${chalk.red.bold(riskScore.counts.critical.toString())}\n`;
  output += `  ${SEVERITY_ICONS.high} High: ${chalk.red(riskScore.counts.high.toString())}\n`;
  output += `  ${SEVERITY_ICONS.medium} Medium: ${chalk.yellow(riskScore.counts.medium.toString())}\n`;
  output += `  ${SEVERITY_ICONS.low} Low: ${chalk.blue(riskScore.counts.low.toString())}\n`;

  return output;
}

/**
 * Format the full scan result for console output
 */
export function formatScanResult(result: ScanResult, options: {
  showContext?: boolean;
  groupBy?: 'file' | 'category' | 'severity';
  verbose?: boolean;
} = {}): string {
  const { showContext = false, groupBy = 'severity', verbose = false } = options;

  let output = '';

  // Header
  output += chalk.bold.cyan('\n🔍 Agent Security Scan Results\n');
  output += chalk.gray('═'.repeat(50)) + '\n\n';

  // Summary
  output += `Files scanned: ${chalk.cyan(result.filesScanned.toString())}\n`;
  output += `Patterns checked: ${chalk.cyan(result.patternsChecked.toString())}\n`;
  output += `Duration: ${chalk.cyan(`${result.duration}ms`)}\n`;
  output += `Total findings: ${chalk.cyan(result.findings.length.toString())}\n\n`;

  if (result.findings.length === 0) {
    output += chalk.green.bold('✅ No security issues found!\n');
    return output;
  }

  // Findings
  output += chalk.bold('📋 Findings\n');
  output += chalk.gray('─'.repeat(40)) + '\n\n';

  if (groupBy === 'file') {
    const byFile = groupFindingsByFile(result.findings);
    for (const [file, findings] of byFile) {
      output += chalk.bold.underline(`\n${file}\n`);
      for (const finding of findings) {
        output += formatFinding(finding, showContext) + '\n';
      }
    }
  } else if (groupBy === 'category') {
    const byCategory = groupFindingsByCategory(result.findings);
    for (const [category, findings] of byCategory) {
      output += chalk.bold.underline(`\n${category} (${findings.length})\n`);
      for (const finding of findings) {
        output += formatFinding(finding, showContext) + '\n';
      }
    }
  } else {
    // Group by severity (default)
    for (const severity of ['critical', 'high', 'medium', 'low'] as Severity[]) {
      const findings = result.findings.filter((f) => f.pattern.severity === severity);
      if (findings.length > 0) {
        output += chalk.bold(`\n${SEVERITY_COLORS[severity](severity.toUpperCase())} (${findings.length})\n`);
        for (const finding of findings) {
          output += formatFinding(finding, showContext) + '\n';
        }
      }
    }
  }

  // Risk score
  output += formatRiskScore(result);

  // Recommendations
  if (result.riskScore.level === 'critical' || result.riskScore.level === 'high') {
    output += chalk.bold.red('\n⚠️  Action Required\n');
    output += chalk.red('This codebase has significant security vulnerabilities.\n');
    output += chalk.red('Address critical and high severity findings before deployment.\n');
  }

  return output;
}

/**
 * Print scan result to console
 */
export function printScanResult(result: ScanResult, options: {
  showContext?: boolean;
  groupBy?: 'file' | 'category' | 'severity';
  verbose?: boolean;
} = {}): void {
  console.log(formatScanResult(result, options));
}
