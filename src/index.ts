#!/usr/bin/env node
/**
 * Agent Security Scanner CLI
 *
 * Security auditing tool for AI agent architectures.
 *
 * Usage:
 *   te-agent-security scan <path>        - Scan directory for vulnerabilities
 *   te-agent-security scan -f <file>     - Scan single file
 *   te-agent-security patterns           - List available patterns
 *   te-agent-security stats              - Show pattern statistics
 */

import { program } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { writeFile } from 'fs/promises';
import { resolve } from 'path';

import { scanDirectory, scanFile, scanContent } from './scanner/index.js';
import { printScanResult, formatScanResult } from './reporters/console.js';
import { formatAsJson } from './reporters/json.js';
import { ALL_PATTERNS, getPatternStats, getPatternsByCategory } from './patterns/index.js';
import type { Severity } from './patterns/types.js';

const VERSION = '1.1.0';

program
  .name('te-agent-security')
  .description('Security scanner for AI agent architectures')
  .version(VERSION);

// Scan command
program
  .command('scan [path]')
  .description('Scan directory or file for security vulnerabilities')
  .option('-f, --file <file>', 'Scan a single file')
  .option('-s, --severity <level>', 'Minimum severity (critical, high, medium, low)', 'medium')
  .option('-o, --output <file>', 'Output file path')
  .option('--format <format>', 'Output format (console, json)', 'console')
  .option('--context', 'Show code context for findings')
  .option('--group <by>', 'Group findings by (severity, file, category, classification)', 'severity')
  .option('-v, --verbose', 'Verbose output')
  .option('-q, --quiet', 'Quiet mode - only show errors')
  .action(async (path, options) => {
    const targetPath = options.file || path || process.cwd();
    const resolvedPath = resolve(targetPath);

    const spinner = options.quiet ? null : ora('Scanning for security issues...').start();

    try {
      const result = options.file
        ? await (async () => {
            const findings = await scanFile(resolvedPath, {
              minSeverity: options.severity as Severity,
            });
            const criticalCount = findings.filter((f) => f.pattern.severity === 'critical').length;
            const highCount = findings.filter((f) => f.pattern.severity === 'high').length;
            const mediumCount = findings.filter((f) => f.pattern.severity === 'medium').length;
            const lowCount = findings.filter((f) => f.pattern.severity === 'low').length;

            const level: 'critical' | 'high' | 'moderate' | 'low' =
              criticalCount > 0 ? 'critical' : findings.length > 5 ? 'high' : findings.length > 0 ? 'moderate' : 'low';

            return {
              filesScanned: 1,
              patternsChecked: ALL_PATTERNS.length,
              findings,
              riskScore: {
                total: 100 - findings.length * 10,
                level,
                counts: {
                  critical: criticalCount,
                  high: highCount,
                  medium: mediumCount,
                  low: lowCount,
                },
                owaspCompliance: 100,
              },
              duration: 0,
              timestamp: new Date(),
            };
          })()
        : await scanDirectory(resolvedPath, {
            minSeverity: options.severity as Severity,
          });

      spinner?.stop();

      // Format output
      if (options.format === 'json') {
        const jsonOutput = formatAsJson(result);
        if (options.output) {
          await writeFile(options.output, jsonOutput);
          console.log(chalk.green(`Results written to ${options.output}`));
        } else {
          console.log(jsonOutput);
        }
      } else {
        const consoleOutput = formatScanResult(result, {
          showContext: options.context,
          groupBy: options.group,
          verbose: options.verbose,
        });

        if (options.output) {
          // Strip ANSI codes for file output
          const plainOutput = consoleOutput.replace(/\x1B\[[0-9;]*[mK]/g, '');
          await writeFile(options.output, plainOutput);
          console.log(chalk.green(`Results written to ${options.output}`));
        } else {
          console.log(consoleOutput);
        }
      }

      // Exit with error code if critical findings
      if (result.riskScore.counts.critical > 0) {
        process.exit(1);
      }
    } catch (error) {
      spinner?.fail('Scan failed');
      console.error(chalk.red(`Error: ${error instanceof Error ? error.message : error}`));
      process.exit(1);
    }
  });

// Patterns command
program
  .command('patterns')
  .description('List available detection patterns')
  .option('-c, --category <category>', 'Filter by category')
  .option('-s, --severity <level>', 'Filter by severity')
  .option('--json', 'Output as JSON')
  .action((options) => {
    let patterns = ALL_PATTERNS;

    if (options.category) {
      patterns = getPatternsByCategory(options.category);
    }

    if (options.severity) {
      patterns = patterns.filter((p) => p.severity === options.severity);
    }

    if (options.json) {
      console.log(
        JSON.stringify(
          patterns.map((p) => ({
            name: p.name,
            severity: p.severity,
            category: p.category,
            description: p.description,
            source: p.source,
          })),
          null,
          2
        )
      );
      return;
    }

    console.log(chalk.bold.cyan('\n📚 Detection Patterns\n'));
    console.log(chalk.gray('─'.repeat(60)));

    for (const pattern of patterns) {
      const severityColor =
        pattern.severity === 'critical'
          ? chalk.red
          : pattern.severity === 'high'
            ? chalk.yellow
            : pattern.severity === 'medium'
              ? chalk.blue
              : chalk.gray;

      console.log(`\n${chalk.bold(pattern.name)}`);
      console.log(`  Severity: ${severityColor(pattern.severity)}`);
      console.log(`  Category: ${chalk.cyan(pattern.category)}`);
      console.log(`  Source: ${chalk.gray(pattern.source)}`);
      console.log(`  ${pattern.description}`);
      if (pattern.example) {
        console.log(`  Example: ${chalk.dim(pattern.example)}`);
      }
    }

    console.log(`\n${chalk.gray('─'.repeat(60))}`);
    console.log(`Total: ${patterns.length} patterns\n`);
  });

// Stats command
program
  .command('stats')
  .description('Show pattern library statistics')
  .option('--json', 'Output as JSON')
  .action((options) => {
    const stats = getPatternStats();

    if (options.json) {
      console.log(JSON.stringify(stats, null, 2));
      return;
    }

    console.log(chalk.bold.cyan('\n📊 Pattern Library Statistics\n'));
    console.log(chalk.gray('═'.repeat(40)));

    console.log(`\n${chalk.bold('Total Patterns:')} ${chalk.cyan(stats.total)}\n`);

    console.log(chalk.bold('By Severity:'));
    console.log(`  Critical: ${chalk.red(stats.bySeverity.critical)}`);
    console.log(`  High: ${chalk.yellow(stats.bySeverity.high)}`);
    console.log(`  Medium: ${chalk.blue(stats.bySeverity.medium)}`);
    console.log(`  Low: ${chalk.gray(stats.bySeverity.low)}`);

    console.log(chalk.bold('\nBy Category:'));
    const categories = Object.entries(stats.byCategory).sort((a, b) => b[1] - a[1]);
    for (const [category, count] of categories) {
      console.log(`  ${category}: ${chalk.cyan(count)}`);
    }

    console.log();
  });

// Version info
program
  .command('version')
  .description('Show version information')
  .action(() => {
    console.log(chalk.bold.cyan('\n🔒 Agent Security Scanner'));
    console.log(`Version: ${VERSION}`);
    console.log(`Patterns: ${ALL_PATTERNS.length}`);
    console.log(`Node: ${process.version}`);
    console.log();
  });

program.parse();
