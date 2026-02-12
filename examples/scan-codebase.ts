#!/usr/bin/env node
/**
 * Example: Scanning a Codebase for Security Issues
 *
 * This example demonstrates how to scan an entire directory for
 * AI agent security vulnerabilities using the agent-security scanner.
 *
 * Usage:
 *   ts-node examples/scan-codebase.ts <directory>
 *   npm run build && node dist/examples/scan-codebase.js <directory>
 */

import { scanDirectory } from '../src/scanner/index.js';
import { ConsoleReporter } from '../src/reporters/console.js';
import { JsonReporter } from '../src/reporters/json.js';

async function main() {
  const targetDir = process.argv[2] || './';

  console.log(`Scanning directory: ${targetDir}\n`);

  try {
    // Scan the directory with options
    const result = await scanDirectory(targetDir, {
      // Exclude common directories
      exclude: [
        'node_modules',
        'dist',
        'build',
        '.git',
        'coverage',
        '.next',
        '.vscode',
      ],
      // Only show high and critical findings
      minSeverity: 'medium',
    });

    // Display results using console reporter
    const consoleReporter = new ConsoleReporter();
    consoleReporter.report(result);

    console.log('\n--- Summary ---');
    console.log(`Files scanned: ${result.filesScanned}`);
    console.log(`Patterns checked: ${result.patternsChecked}`);
    console.log(`Total findings: ${result.findings.length}`);
    console.log(`Risk score: ${result.riskScore.total}/100 (${result.riskScore.level})`);
    console.log(`Duration: ${result.duration}ms`);

    // Optionally save JSON report
    const jsonReporter = new JsonReporter();
    const jsonOutput = jsonReporter.report(result);
    console.log('\nJSON report available in output');

    // Exit with error code if critical issues found
    if (result.riskScore.level === 'critical') {
      console.error('\n❌ Critical security issues detected. Do not deploy.');
      process.exit(1);
    } else if (result.riskScore.level === 'high') {
      console.warn('\n⚠️  High-risk issues detected. Review before deployment.');
      process.exit(0);
    } else {
      console.log('\n✅ Security scan complete.');
      process.exit(0);
    }
  } catch (error) {
    console.error('Scan failed:', error);
    process.exit(1);
  }
}

main();
