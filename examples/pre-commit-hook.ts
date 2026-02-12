#!/usr/bin/env node
/**
 * Example: Git Pre-Commit Hook
 *
 * This example shows how to use agent-security as a pre-commit hook
 * to prevent insecure code from being committed.
 *
 * Installation:
 *   1. Copy this file to .git/hooks/pre-commit
 *   2. Make it executable: chmod +x .git/hooks/pre-commit
 *   3. Optionally add to package.json scripts:
 *      "prepare": "husky install && cp examples/pre-commit-hook.js .git/hooks/pre-commit"
 *
 * The hook will:
 *   - Scan only staged files (what's about to be committed)
 *   - Block commits with critical or high severity issues
 *   - Allow commits with medium/low issues (but warn)
 */

import { scanFile } from '../src/scanner/index.js';
import { matchPatterns, ALL_PATTERNS } from '../src/patterns/index.js';
import { execSync } from 'child_process';
import * as fs from 'fs';

async function main() {
  console.log('🔍 Running agent security scan on staged files...\n');

  try {
    // Get list of staged files
    const stagedFiles = execSync('git diff --cached --name-only --diff-filter=ACM', {
      encoding: 'utf-8',
    })
      .trim()
      .split('\n')
      .filter((f) => f.length > 0)
      .filter((f) => {
        // Only scan text files (exclude binaries, images, etc.)
        const textExtensions = ['.ts', '.js', '.tsx', '.jsx', '.json', '.md', '.txt', '.env', '.yaml', '.yml'];
        return textExtensions.some((ext) => f.endsWith(ext));
      });

    if (stagedFiles.length === 0) {
      console.log('No text files staged for commit.');
      process.exit(0);
    }

    console.log(`Scanning ${stagedFiles.length} staged files...\n`);

    let allFindings: any[] = [];

    // Scan each staged file
    for (const file of stagedFiles) {
      if (!fs.existsSync(file)) continue;

      const content = fs.readFileSync(file, 'utf-8');
      const findings = matchPatterns(ALL_PATTERNS, content, file);

      if (findings.length > 0) {
        allFindings.push(...findings);
      }
    }

    // Categorize findings
    const critical = allFindings.filter((f) => f.pattern.severity === 'critical');
    const high = allFindings.filter((f) => f.pattern.severity === 'high');
    const medium = allFindings.filter((f) => f.pattern.severity === 'medium');
    const low = allFindings.filter((f) => f.pattern.severity === 'low');

    // Print results
    if (allFindings.length === 0) {
      console.log('✅ No security issues detected in staged files.');
      process.exit(0);
    }

    console.log('--- Security Issues Found ---\n');

    if (critical.length > 0) {
      console.log(`🚨 Critical Issues (${critical.length}):`);
      critical.forEach((f) => {
        console.log(`  • ${f.file}:${f.line}:${f.column}`);
        console.log(`    ${f.pattern.description}`);
        console.log(`    Matched: "${f.match}"`);
        if (f.pattern.remediation) {
          console.log(`    Fix: ${f.pattern.remediation}`);
        }
        console.log();
      });
    }

    if (high.length > 0) {
      console.log(`⚠️  High Severity Issues (${high.length}):`);
      high.forEach((f) => {
        console.log(`  • ${f.file}:${f.line}:${f.column} - ${f.pattern.description}`);
      });
      console.log();
    }

    if (medium.length > 0) {
      console.log(`ℹ️  Medium Severity Issues (${medium.length}):`);
      medium.forEach((f) => {
        console.log(`  • ${f.file}:${f.line}:${f.column} - ${f.pattern.description}`);
      });
      console.log();
    }

    // Determine whether to block the commit
    if (critical.length > 0 || high.length > 0) {
      console.error('❌ Commit blocked: Critical or high severity security issues detected.');
      console.error('Please fix the issues above before committing.\n');
      console.error('To bypass this check (NOT RECOMMENDED):');
      console.error('  git commit --no-verify\n');
      process.exit(1);
    } else if (medium.length > 0) {
      console.warn('⚠️  Warning: Medium severity issues detected.');
      console.warn('Please review these issues before deploying.\n');
      console.log('✅ Commit allowed (but please review findings).');
      process.exit(0);
    } else {
      console.log('✅ All findings are low severity. Commit allowed.');
      process.exit(0);
    }
  } catch (error) {
    console.error('Hook execution failed:', error);
    // Don't block commits on hook errors (fail open)
    console.warn('⚠️  Security scan failed, but allowing commit to proceed.');
    process.exit(0);
  }
}

main();
