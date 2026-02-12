#!/usr/bin/env node
/**
 * Example: GitHub Actions CI/CD Integration
 *
 * This example demonstrates how to integrate agent-security scanning
 * into a CI/CD pipeline. It exits with appropriate error codes for
 * automated build systems.
 *
 * Usage in GitHub Actions:
 *   - run: node dist/examples/ci-integration.js
 *
 * Exit codes:
 *   0 - No critical or high severity issues
 *   1 - Critical or high severity issues found
 */

import { scanDirectory } from '../src/scanner/index.js';
import { JsonReporter } from '../src/reporters/json.js';
import * as fs from 'fs';
import * as path from 'path';

async function main() {
  const workspaceDir = process.env.GITHUB_WORKSPACE || process.cwd();
  const failOnSeverity = (process.env.FAIL_ON_SEVERITY || 'high') as
    | 'critical'
    | 'high'
    | 'medium'
    | 'low';

  console.log('🔍 Agent Security Scanner - CI Mode');
  console.log(`Workspace: ${workspaceDir}`);
  console.log(`Fail threshold: ${failOnSeverity}\n`);

  try {
    const result = await scanDirectory(workspaceDir, {
      exclude: ['node_modules', 'dist', 'build', '.git', 'coverage'],
      minSeverity: 'medium',
    });

    // Save JSON report for artifacts
    const jsonReporter = new JsonReporter();
    const jsonReport = jsonReporter.report(result);
    const reportPath = path.join(workspaceDir, 'agent-security-report.json');
    fs.writeFileSync(reportPath, jsonReport);
    console.log(`📄 Report saved: ${reportPath}\n`);

    // Print summary
    console.log('--- Scan Summary ---');
    console.log(`Files scanned: ${result.filesScanned}`);
    console.log(`Total findings: ${result.findings.length}`);
    console.log(
      `Critical: ${result.riskScore.counts.critical}, High: ${result.riskScore.counts.high}, Medium: ${result.riskScore.counts.medium}`
    );
    console.log(`Risk level: ${result.riskScore.level}`);
    console.log(`OWASP ASI compliance: ${result.riskScore.owaspCompliance}%\n`);

    // Print findings by severity
    if (result.findings.length > 0) {
      console.log('--- Findings ---');
      const criticalFindings = result.findings.filter((f) => f.pattern.severity === 'critical');
      const highFindings = result.findings.filter((f) => f.pattern.severity === 'high');

      if (criticalFindings.length > 0) {
        console.log(`\n🚨 Critical Issues (${criticalFindings.length}):`);
        criticalFindings.slice(0, 5).forEach((f) => {
          console.log(`  • ${f.file}:${f.line} - ${f.pattern.description}`);
        });
        if (criticalFindings.length > 5) {
          console.log(`  ... and ${criticalFindings.length - 5} more`);
        }
      }

      if (highFindings.length > 0) {
        console.log(`\n⚠️  High Severity Issues (${highFindings.length}):`);
        highFindings.slice(0, 5).forEach((f) => {
          console.log(`  • ${f.file}:${f.line} - ${f.pattern.description}`);
        });
        if (highFindings.length > 5) {
          console.log(`  ... and ${highFindings.length - 5} more`);
        }
      }
    }

    // Determine pass/fail based on threshold
    const severityOrder = ['low', 'medium', 'high', 'critical'];
    const thresholdIndex = severityOrder.indexOf(failOnSeverity);

    const failingFindings = result.findings.filter((f) => {
      const findingSeverityIndex = severityOrder.indexOf(f.pattern.severity);
      return findingSeverityIndex >= thresholdIndex;
    });

    if (failingFindings.length > 0) {
      console.log(
        `\n❌ Build failed: ${failingFindings.length} findings at or above '${failOnSeverity}' severity`
      );
      console.log('See agent-security-report.json for details');

      // Set GitHub Actions output
      if (process.env.GITHUB_OUTPUT) {
        fs.appendFileSync(
          process.env.GITHUB_OUTPUT,
          `security_status=failed\nfindings_count=${failingFindings.length}\n`
        );
      }

      process.exit(1);
    } else {
      console.log('\n✅ Security scan passed');

      // Set GitHub Actions output
      if (process.env.GITHUB_OUTPUT) {
        fs.appendFileSync(
          process.env.GITHUB_OUTPUT,
          `security_status=passed\nfindings_count=${result.findings.length}\n`
        );
      }

      process.exit(0);
    }
  } catch (error) {
    console.error('❌ Scan failed:', error);
    process.exit(1);
  }
}

main();
