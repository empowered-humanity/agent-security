/**
 * Content Scanner
 *
 * Scans text content (prompts, configs, code) for security patterns.
 */

import { readFile } from 'fs/promises';
import { glob } from 'glob';
import type { DetectionPattern, Finding, ScanResult } from '../patterns/types.js';
import { matchPatterns, createScanResult } from './engine.js';
import { ALL_PATTERNS, getPatternsMinSeverity } from '../patterns/index.js';

export interface ScanOptions {
  /** Patterns to use (defaults to all) */
  patterns?: DetectionPattern[];
  /** Minimum severity to report */
  minSeverity?: 'critical' | 'high' | 'medium' | 'low';
  /** File patterns to include */
  include?: string[];
  /** File patterns to exclude */
  exclude?: string[];
}

const DEFAULT_INCLUDE = [
  '**/*.ts',
  '**/*.tsx',
  '**/*.js',
  '**/*.jsx',
  '**/*.py',
  '**/*.md',
  '**/*.txt',
  '**/*.xml',
  '**/*.yaml',
  '**/*.yml',
  '**/*.json',
  '**/*.env*',
];

const DEFAULT_EXCLUDE = [
  '**/node_modules/**',
  '**/dist/**',
  '**/build/**',
  '**/.git/**',
  '**/coverage/**',
  '**/*.min.js',
  '**/package-lock.json',
  '**/pnpm-lock.yaml',
  '**/yarn.lock',
];

/**
 * Scan a single file for security patterns
 */
export async function scanFile(
  filePath: string,
  options: ScanOptions = {}
): Promise<Finding[]> {
  const patterns = options.patterns ||
    (options.minSeverity ? getPatternsMinSeverity(options.minSeverity) : ALL_PATTERNS);

  try {
    const content = await readFile(filePath, 'utf-8');
    return matchPatterns(patterns, content, filePath);
  } catch (error) {
    // File couldn't be read (binary, permission, etc.)
    return [];
  }
}

/**
 * Scan content string directly
 */
export function scanContent(
  content: string,
  source: string = '<input>',
  options: ScanOptions = {}
): Finding[] {
  const patterns = options.patterns ||
    (options.minSeverity ? getPatternsMinSeverity(options.minSeverity) : ALL_PATTERNS);

  return matchPatterns(patterns, content, source);
}

/**
 * Scan a directory for security patterns
 */
export async function scanDirectory(
  dirPath: string,
  options: ScanOptions = {}
): Promise<ScanResult> {
  const startTime = Date.now();

  const patterns = options.patterns ||
    (options.minSeverity ? getPatternsMinSeverity(options.minSeverity) : ALL_PATTERNS);

  const include = options.include || DEFAULT_INCLUDE;
  const exclude = options.exclude || DEFAULT_EXCLUDE;

  // Find all matching files
  const files: string[] = [];
  for (const pattern of include) {
    const matches = await glob(pattern, {
      cwd: dirPath,
      absolute: true,
      ignore: exclude,
      nodir: true,
    });
    files.push(...matches);
  }

  // Deduplicate files
  const uniqueFiles = [...new Set(files)];

  // Scan all files
  const allFindings: Finding[] = [];
  for (const file of uniqueFiles) {
    const findings = await scanFile(file, { patterns });
    allFindings.push(...findings);
  }

  return createScanResult(uniqueFiles.length, patterns.length, allFindings, startTime);
}

/**
 * Quick scan - only critical and high severity
 */
export async function quickScan(dirPath: string): Promise<ScanResult> {
  return scanDirectory(dirPath, { minSeverity: 'high' });
}

/**
 * Full scan - all severities
 */
export async function fullScan(dirPath: string): Promise<ScanResult> {
  return scanDirectory(dirPath, { minSeverity: 'low' });
}

export { DEFAULT_INCLUDE, DEFAULT_EXCLUDE };
