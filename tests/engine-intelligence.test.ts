/**
 * Intelligence Layer Tests
 *
 * Tests for the 4 intelligence layers added to the pattern matching engine:
 * 1. Context-aware filtering (inferFileContext, shouldApplyPattern)
 * 2. Test file detection + severity downgrade
 * 3. Auto-classification of findings
 * 4. Taint proximity analysis
 * 5. Context flow tracing
 */

import { describe, it, expect } from 'vitest';
import {
  inferFileContext,
  shouldApplyPattern,
  isTestFile,
  classifyFinding,
  analyzeTaintProximity,
  traceContextFlow,
  matchPattern,
  matchPatterns,
  groupFindingsByClassification,
} from '../src/scanner/engine.js';
import type { DetectionPattern, Finding, Severity } from '../src/patterns/types.js';

// ═══════════════════════════════════════════════════════════
// Helper: create a minimal pattern for testing
// ═══════════════════════════════════════════════════════════

function makePattern(overrides: Partial<DetectionPattern> = {}): DetectionPattern {
  return {
    name: 'test_pattern',
    pattern: /test/,
    severity: 'high' as Severity,
    category: 'code_injection',
    description: 'Test pattern',
    source: 'test',
    ...overrides,
  };
}

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    pattern: makePattern(),
    file: 'src/main.ts',
    line: 1,
    column: 1,
    match: 'test',
    context: 'test context',
    timestamp: new Date(),
    classification: 'unclassified',
    originalSeverity: 'high',
    severityDowngraded: false,
    isTestFile: false,
    ...overrides,
  };
}

// ═══════════════════════════════════════════════════════════
// 1. Context-Aware Filtering
// ═══════════════════════════════════════════════════════════

describe('inferFileContext', () => {
  it('should identify code files', () => {
    expect(inferFileContext('src/main.ts')).toBe('code');
    expect(inferFileContext('app.py')).toBe('code');
    expect(inferFileContext('lib/utils.js')).toBe('code');
    expect(inferFileContext('handler.go')).toBe('code');
    expect(inferFileContext('main.rs')).toBe('code');
    expect(inferFileContext('App.java')).toBe('code');
    expect(inferFileContext('script.sh')).toBe('code');
  });

  it('should identify config files', () => {
    expect(inferFileContext('config.json')).toBe('config');
    expect(inferFileContext('settings.yaml')).toBe('config');
    expect(inferFileContext('app.yml')).toBe('config');
    expect(inferFileContext('config.toml')).toBe('config');
    expect(inferFileContext('settings.xml')).toBe('config');
  });

  it('should identify prompt/doc files', () => {
    expect(inferFileContext('README.md')).toBe('prompt');
    expect(inferFileContext('notes.txt')).toBe('prompt');
    expect(inferFileContext('guide.rst')).toBe('prompt');
  });

  it('should identify .env files as config', () => {
    expect(inferFileContext('.env')).toBe('config');
    expect(inferFileContext('.env.local')).toBe('config');
    expect(inferFileContext('.env.production')).toBe('config');
  });

  it('should identify dependency files', () => {
    expect(inferFileContext('package.json')).toBe('dependency_version');
    expect(inferFileContext('requirements.txt')).toBe('dependency_version');
    expect(inferFileContext('Cargo.toml')).toBe('dependency_version');
    expect(inferFileContext('go.mod')).toBe('dependency_version');
    expect(inferFileContext('Gemfile')).toBe('dependency_version');
  });

  it('should return any for unknown extensions', () => {
    expect(inferFileContext('file.xyz')).toBe('any');
    expect(inferFileContext('noext')).toBe('any');
  });

  it('should handle Windows paths', () => {
    expect(inferFileContext('C:\\code\\src\\main.ts')).toBe('code');
    expect(inferFileContext('C:\\Users\\.env')).toBe('config');
  });
});

describe('shouldApplyPattern', () => {
  it('should apply patterns with no context to any file', () => {
    const pattern = makePattern({ context: undefined });
    expect(shouldApplyPattern(pattern, 'anything.ts')).toBe(true);
  });

  it('should apply patterns with context "any" to any file', () => {
    const pattern = makePattern({ context: 'any' });
    expect(shouldApplyPattern(pattern, 'anything.xyz')).toBe(true);
  });

  it('should skip runtime-only patterns during static scanning', () => {
    const pattern = makePattern({ context: 'file_write_operation' });
    expect(shouldApplyPattern(pattern, 'src/main.ts')).toBe(false);

    const emailPattern = makePattern({ context: 'email_operation' });
    expect(shouldApplyPattern(emailPattern, 'src/main.ts')).toBe(false);
  });

  it('should apply code patterns only to code files', () => {
    const pattern = makePattern({ context: 'code' });
    expect(shouldApplyPattern(pattern, 'src/main.ts')).toBe(true);
    expect(shouldApplyPattern(pattern, 'README.md')).toBe(false);
    expect(shouldApplyPattern(pattern, 'config.json')).toBe(false);
  });

  it('should apply prompt patterns only to prompt files', () => {
    const pattern = makePattern({ context: 'prompt' });
    expect(shouldApplyPattern(pattern, 'README.md')).toBe(true);
    expect(shouldApplyPattern(pattern, 'notes.txt')).toBe(true);
    expect(shouldApplyPattern(pattern, 'src/main.ts')).toBe(false);
  });

  it('should apply config patterns to config and dependency files', () => {
    const pattern = makePattern({ context: 'config' });
    expect(shouldApplyPattern(pattern, 'config.json')).toBe(true);
    expect(shouldApplyPattern(pattern, 'package.json')).toBe(true);
    expect(shouldApplyPattern(pattern, 'src/main.ts')).toBe(false);
  });

  it('should apply dependency_version patterns only to dependency files', () => {
    const pattern = makePattern({ context: 'dependency_version' });
    expect(shouldApplyPattern(pattern, 'package.json')).toBe(true);
    expect(shouldApplyPattern(pattern, 'requirements.txt')).toBe(true);
    expect(shouldApplyPattern(pattern, 'config.json')).toBe(false);
    expect(shouldApplyPattern(pattern, 'src/main.ts')).toBe(false);
  });

  it('should apply patterns to unknown file types (any context)', () => {
    const pattern = makePattern({ context: 'code' });
    expect(shouldApplyPattern(pattern, 'file.xyz')).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════
// 2. Test File Detection
// ═══════════════════════════════════════════════════════════

describe('isTestFile', () => {
  it('should detect test directories', () => {
    expect(isTestFile('src/tests/main.ts')).toBe(true);
    expect(isTestFile('src/test/main.ts')).toBe(true);
    expect(isTestFile('src/__tests__/main.ts')).toBe(true);
  });

  it('should detect test file suffixes', () => {
    expect(isTestFile('main.test.ts')).toBe(true);
    expect(isTestFile('main.spec.ts')).toBe(true);
    expect(isTestFile('main_test.py')).toBe(true);
    expect(isTestFile('test_main.py')).toBe(true);
  });

  it('should detect fixture and mock directories', () => {
    expect(isTestFile('src/fixtures/data.json')).toBe(true);
    expect(isTestFile('src/fixture/data.json')).toBe(true);
    expect(isTestFile('src/mocks/api.ts')).toBe(true);
    expect(isTestFile('src/mock/api.ts')).toBe(true);
    expect(isTestFile('src/stubs/service.ts')).toBe(true);
  });

  it('should detect example directories', () => {
    expect(isTestFile('src/examples/demo.py')).toBe(true);
    expect(isTestFile('src/example/demo.py')).toBe(true);
  });

  it('should detect payload and data directories', () => {
    expect(isTestFile('src/data/payloads/injection.json')).toBe(true);
    expect(isTestFile('src/payloads/xss.txt')).toBe(true);
    expect(isTestFile('src/resources/config.yaml')).toBe(true);
    expect(isTestFile('src/samples/demo.py')).toBe(true);
  });

  it('should NOT detect production files', () => {
    expect(isTestFile('src/main.ts')).toBe(false);
    expect(isTestFile('lib/utils.py')).toBe(false);
    expect(isTestFile('app/handler.go')).toBe(false);
    expect(isTestFile('index.js')).toBe(false);
  });

  it('should handle Windows paths', () => {
    expect(isTestFile('C:\\code\\tests\\main.ts')).toBe(true);
    expect(isTestFile('C:\\code\\src\\main.ts')).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════
// 3. Auto-Classification
// ═══════════════════════════════════════════════════════════

describe('classifyFinding', () => {
  it('should classify injection in test files as test_payload', () => {
    const finding = makeFinding({
      pattern: makePattern({ category: 'instruction_override' }),
      isTestFile: true,
    });
    expect(classifyFinding(finding)).toBe('test_payload');
  });

  it('should classify injection in production as live_vulnerability', () => {
    const finding = makeFinding({
      pattern: makePattern({ category: 'instruction_override' }),
      isTestFile: false,
    });
    expect(classifyFinding(finding)).toBe('live_vulnerability');
  });

  it('should classify credential patterns as credential_exposure', () => {
    const finding = makeFinding({
      pattern: makePattern({ category: 'credential_exposure' }),
    });
    expect(classifyFinding(finding)).toBe('credential_exposure');
  });

  it('should classify supply chain patterns', () => {
    const finding = makeFinding({
      pattern: makePattern({ name: 'mcp_version_unpinned', category: 'supply_chain' }),
    });
    expect(classifyFinding(finding)).toBe('supply_chain_risk');
  });

  it('should classify ASI04 as supply chain', () => {
    const finding = makeFinding({
      pattern: makePattern({ category: 'ASI04_supply_chain' }),
    });
    expect(classifyFinding(finding)).toBe('supply_chain_risk');
  });

  it('should classify config patterns', () => {
    const finding = makeFinding({
      pattern: makePattern({ category: 'config_vulnerability' }),
    });
    expect(classifyFinding(finding)).toBe('configuration_risk');
  });

  it('should classify CAPE patterns as architectural_weakness', () => {
    const finding = makeFinding({
      pattern: makePattern({ category: 'cross_agent_escalation' }),
    });
    expect(classifyFinding(finding)).toBe('architectural_weakness');
  });

  it('should classify MCP attack patterns as architectural_weakness', () => {
    const finding = makeFinding({
      pattern: makePattern({ category: 'mcp_attack' }),
    });
    expect(classifyFinding(finding)).toBe('architectural_weakness');
  });

  it('should classify code injection as live_vulnerability', () => {
    const finding = makeFinding({
      pattern: makePattern({ category: 'code_injection' }),
    });
    expect(classifyFinding(finding)).toBe('live_vulnerability');
  });

  it('should classify code injection in test files as test_payload', () => {
    const finding = makeFinding({
      pattern: makePattern({ category: 'code_injection' }),
      isTestFile: true,
    });
    expect(classifyFinding(finding)).toBe('test_payload');
  });

  it('should classify reconnaissance in prod as live_vulnerability', () => {
    const finding = makeFinding({
      pattern: makePattern({ category: 'reconnaissance' }),
      isTestFile: false,
    });
    expect(classifyFinding(finding)).toBe('live_vulnerability');
  });

  it('should classify reconnaissance in test as test_payload', () => {
    const finding = makeFinding({
      pattern: makePattern({ category: 'reconnaissance' }),
      isTestFile: true,
    });
    expect(classifyFinding(finding)).toBe('test_payload');
  });

  it('should classify data exfiltration in test as test_payload', () => {
    const finding = makeFinding({
      pattern: makePattern({ category: 'data_exfiltration' }),
      isTestFile: true,
    });
    expect(classifyFinding(finding)).toBe('test_payload');
  });

  it('should classify path_traversal', () => {
    const finding = makeFinding({
      pattern: makePattern({ category: 'path_traversal' }),
      isTestFile: false,
    });
    expect(classifyFinding(finding)).toBe('live_vulnerability');
  });

  it('should classify platform_specific', () => {
    const finding = makeFinding({
      pattern: makePattern({ category: 'platform_specific' }),
      isTestFile: false,
    });
    expect(classifyFinding(finding)).toBe('live_vulnerability');
  });
});

// ═══════════════════════════════════════════════════════════
// 4. Taint Proximity Analysis
// ═══════════════════════════════════════════════════════════

describe('analyzeTaintProximity', () => {
  it('should return direct when taint source is on same line', () => {
    const lines = [
      'result = eval(input("Enter code: "))',
    ];
    expect(analyzeTaintProximity(lines, 0)).toBe('direct');
  });

  it('should return direct for request.body on same line', () => {
    const lines = [
      'exec(request.body.code)',
    ];
    expect(analyzeTaintProximity(lines, 0)).toBe('direct');
  });

  it('should return nearby when taint source is within window', () => {
    const lines = [
      'user_code = input("Enter: ")',
      'processed = user_code.strip()',
      'result = eval(processed)',
    ];
    expect(analyzeTaintProximity(lines, 2)).toBe('nearby');
  });

  it('should return nearby for LLM invoke within window', () => {
    const lines = [
      'response = llm.invoke(prompt)',
      'code = response.content',
      '',
      'exec(code)',
    ];
    expect(analyzeTaintProximity(lines, 3)).toBe('nearby');
  });

  it('should return distant when no taint source nearby', () => {
    const lines = [
      'import os',
      'CONFIG = "SELECT * FROM users"',
      'result = eval(CONFIG)',
    ];
    expect(analyzeTaintProximity(lines, 2)).toBe('distant');
  });

  it('should detect argv as taint source', () => {
    const lines = [
      'import sys',
      'code = sys.argv[1]',
      'exec(code)',
    ];
    expect(analyzeTaintProximity(lines, 2)).toBe('nearby');
  });

  it('should detect user_input variable as taint source', () => {
    const lines = Array(15).fill('# filler line');
    lines[0] = 'user_input = get_input()';
    lines[5] = 'eval(processed)';
    expect(analyzeTaintProximity(lines, 5)).toBe('nearby');
  });

  it('should NOT detect sources beyond window', () => {
    const lines = Array(25).fill('# filler line');
    lines[0] = 'user_input = get_input()';
    lines[20] = 'eval(something)';
    expect(analyzeTaintProximity(lines, 20)).toBe('distant');
  });
});

// ═══════════════════════════════════════════════════════════
// 5. Context Flow Tracing
// ═══════════════════════════════════════════════════════════

describe('traceContextFlow', () => {
  it('should detect serialization followed by external call', () => {
    const lines = [
      'const data = prepareData();',
      'const body = JSON.stringify({ context: messages });',
      'const result = await fetch(url, { body });',
    ];
    const chain = traceContextFlow(lines, 1);
    expect(chain).toBeDefined();
    expect(chain!.length).toBe(2);
    expect(chain![0]).toContain('serialize@L2');
    expect(chain![1]).toContain('external_call@L3');
  });

  it('should detect serialization with preceding external call', () => {
    const lines = [
      'const response = await axios.post(url);',
      'const log = JSON.stringify({ messages: conversation });',
    ];
    const chain = traceContextFlow(lines, 1);
    expect(chain).toBeDefined();
    expect(chain!.length).toBe(2);
    expect(chain![0]).toContain('serialize@L2');
    expect(chain![1]).toContain('external_call@L1');
  });

  it('should return undefined when no external call nearby', () => {
    const lines = [
      'const log = JSON.stringify({ messages: conversation });',
      'console.log(log);',
      'return log;',
    ];
    const chain = traceContextFlow(lines, 0);
    expect(chain).toBeUndefined();
  });

  it('should detect tool_call as external', () => {
    const lines = [
      'const ctx = JSON.stringify(context.messages);',
      'const result = tool_call(toolName, ctx);',
    ];
    const chain = traceContextFlow(lines, 0);
    expect(chain).toBeDefined();
    expect(chain![1]).toContain('tool_call');
  });

  it('should detect Python dump as serialization', () => {
    const lines = [
      'data = json.dump(conversation)',
      'requests.post(url, data=data)',
    ];
    const chain = traceContextFlow(lines, 0);
    expect(chain).toBeDefined();
  });
});

// ═══════════════════════════════════════════════════════════
// 6. Integration: matchPattern with intelligence
// ═══════════════════════════════════════════════════════════

describe('matchPattern integration', () => {
  it('should set classification on findings', () => {
    const pattern = makePattern({
      pattern: /eval\(/,
      category: 'code_injection',
      context: 'code',
    });
    const findings = matchPattern(pattern, 'result = eval(x)', 'src/main.py');
    expect(findings.length).toBe(1);
    expect(findings[0].classification).toBe('live_vulnerability');
  });

  it('should downgrade severity for test files', () => {
    const pattern = makePattern({
      pattern: /password\s*=/i,
      severity: 'critical',
      category: 'credential_exposure',
    });
    const findings = matchPattern(pattern, 'password = "test123"', 'tests/auth.test.ts');
    expect(findings.length).toBe(1);
    expect(findings[0].severityDowngraded).toBe(true);
    expect(findings[0].originalSeverity).toBe('critical');
    expect(findings[0].pattern.severity).toBe('high');
  });

  it('should NOT downgrade severity for production files', () => {
    const pattern = makePattern({
      pattern: /password\s*=/i,
      severity: 'critical',
      category: 'credential_exposure',
    });
    const findings = matchPattern(pattern, 'password = "real123"', 'src/config.ts');
    expect(findings.length).toBe(1);
    expect(findings[0].severityDowngraded).toBe(false);
    expect(findings[0].pattern.severity).toBe('critical');
  });

  it('should set isTestFile flag correctly', () => {
    const pattern = makePattern({ pattern: /test/ });
    const testFindings = matchPattern(pattern, 'test', 'tests/main.test.ts');
    const prodFindings = matchPattern(pattern, 'test', 'src/main.ts');
    expect(testFindings[0].isTestFile).toBe(true);
    expect(prodFindings[0].isTestFile).toBe(false);
  });

  it('should skip prompt patterns on code files', () => {
    const pattern = makePattern({
      pattern: /ignore instructions/i,
      context: 'prompt',
    });
    const findings = matchPattern(pattern, 'ignore instructions', 'src/main.ts');
    expect(findings.length).toBe(0);
  });

  it('should apply prompt patterns to markdown files', () => {
    const pattern = makePattern({
      pattern: /ignore instructions/i,
      context: 'prompt',
      category: 'instruction_override',
    });
    const findings = matchPattern(pattern, 'ignore instructions', 'README.md');
    expect(findings.length).toBe(1);
  });
});

describe('groupFindingsByClassification', () => {
  it('should group findings by their classification', () => {
    const findings: Finding[] = [
      makeFinding({ classification: 'live_vulnerability' }),
      makeFinding({ classification: 'live_vulnerability' }),
      makeFinding({ classification: 'test_payload' }),
      makeFinding({ classification: 'credential_exposure' }),
    ];

    const groups = groupFindingsByClassification(findings);
    expect(groups.get('live_vulnerability')?.length).toBe(2);
    expect(groups.get('test_payload')?.length).toBe(1);
    expect(groups.get('credential_exposure')?.length).toBe(1);
  });
});
