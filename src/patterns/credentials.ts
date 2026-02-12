/**
 * Credential Detection Patterns
 *
 * Patterns for detecting hardcoded credentials, API keys, tokens,
 * and other sensitive information that should not be in code or
 * accessible to AI agents.
 */

import type { DetectionPattern } from './types.js';

/**
 * API Key Patterns
 */
export const apiKeyPatterns: DetectionPattern[] = [
  {
    name: 'openai_api_key',
    pattern: /sk-[a-zA-Z0-9]{20,}/,
    severity: 'critical',
    category: 'credential_exposure',
    source: 'ai-assistant',
    description: 'OpenAI API key detected',
    example: 'sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    remediation: 'Use environment variables or secret management',
  },
  {
    name: 'anthropic_api_key',
    pattern: /sk-ant-[a-zA-Z0-9]{20,}/,
    severity: 'critical',
    category: 'credential_exposure',
    source: 'ai-assistant',
    description: 'Anthropic API key detected',
    example: 'sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  },
  {
    name: 'github_pat',
    pattern: /ghp_[a-zA-Z0-9]{36}/,
    severity: 'critical',
    category: 'credential_exposure',
    source: 'ai-assistant',
    description: 'GitHub Personal Access Token detected',
    example: 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  },
  {
    name: 'github_oauth',
    pattern: /gho_[a-zA-Z0-9]{36}/,
    severity: 'critical',
    category: 'credential_exposure',
    source: 'ai-assistant',
    description: 'GitHub OAuth token detected',
    example: 'gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  },
  {
    name: 'aws_access_key',
    pattern: /AKIA[0-9A-Z]{16}/,
    severity: 'critical',
    category: 'credential_exposure',
    source: 'ai-assistant',
    description: 'AWS Access Key ID detected',
    example: 'AKIAIOSFODNN7EXAMPLE',
  },
  {
    name: 'aws_secret_key',
    pattern: /(?:aws)?_?secret_?(?:access)?_?key["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}/i,
    severity: 'critical',
    category: 'credential_exposure',
    source: 'ai-assistant',
    description: 'AWS Secret Access Key detected',
    example: 'aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
  },
  {
    name: 'google_api_key',
    pattern: /AIza[0-9A-Za-z_-]{35}/,
    severity: 'critical',
    category: 'credential_exposure',
    source: 'ai-assistant',
    description: 'Google API key detected',
    example: 'AIzaSyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  },
  {
    name: 'stripe_key',
    pattern: /(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{24,}/,
    severity: 'critical',
    category: 'credential_exposure',
    source: 'ai-assistant',
    description: 'Stripe API key detected',
    example: 'sk_live_EXAMPLE_REDACTED_KEY_00',
  },
  {
    name: 'slack_token',
    pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/,
    severity: 'critical',
    category: 'credential_exposure',
    source: 'ai-assistant',
    description: 'Slack token detected',
    example: 'xoxb-123456789012-123456789012-xxxxxxxxxxxx',
  },
  {
    name: 'generic_api_key',
    pattern: /(?:api[_-]?key|apikey)\s*[=:]\s*["']?[a-zA-Z0-9_-]{20,}["']?/i,
    severity: 'high',
    category: 'credential_exposure',
    source: 'ai-assistant',
    description: 'Generic API key assignment detected',
    example: 'api_key = "xxxxxxxxxxxxxxxxxxxx"',
  },
];

/**
 * Password and Secret Patterns
 */
export const passwordPatterns: DetectionPattern[] = [
  {
    name: 'password_assignment',
    pattern: /(?:password|passwd|pwd)\s*[=:]\s*["'][^"']+["']/i,
    severity: 'critical',
    category: 'credential_exposure',
    source: 'ai-assistant',
    description: 'Hardcoded password detected',
    example: 'password = "mysecretpassword"',
    remediation: 'Never hardcode passwords; use environment variables',
  },
  {
    name: 'secret_assignment',
    pattern: /(?:secret|token)\s*[=:]\s*["'][^"']{8,}["']/i,
    severity: 'high',
    category: 'credential_exposure',
    source: 'ai-assistant',
    description: 'Hardcoded secret/token detected',
    example: 'secret = "mysecretvalue"',
  },
  {
    name: 'connection_string',
    pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^@]+:[^@]+@/i,
    severity: 'critical',
    category: 'credential_exposure',
    source: 'ai-assistant',
    description: 'Database connection string with credentials',
    example: 'mongodb://user:password@localhost:27017',
  },
];

/**
 * Private Key Patterns
 */
export const privateKeyPatterns: DetectionPattern[] = [
  {
    name: 'rsa_private_key',
    pattern: /-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----/,
    severity: 'critical',
    category: 'credential_exposure',
    source: 'ai-assistant',
    description: 'RSA private key detected',
    example: '-----BEGIN RSA PRIVATE KEY-----',
  },
  {
    name: 'generic_private_key',
    pattern: /-----BEGIN\s+(?:PRIVATE|EC|DSA|OPENSSH)\s+(?:KEY|PRIVATE\s+KEY)-----/,
    severity: 'critical',
    category: 'credential_exposure',
    source: 'ai-assistant',
    description: 'Private key detected',
    example: '-----BEGIN PRIVATE KEY-----',
  },
  {
    name: 'ssh_key',
    pattern: /ssh-(?:rsa|ed25519|dss)\s+[A-Za-z0-9+/=]+/,
    severity: 'high',
    category: 'credential_exposure',
    source: 'ai-assistant',
    description: 'SSH key detected',
    example: 'ssh-rsa AAAAB3NzaC1yc2E...',
  },
];

/**
 * Credential Access Patterns
 * Attempts to access credential files or stores
 */
export const credentialAccessPatterns: DetectionPattern[] = [
  {
    name: 'env_file_access',
    pattern: /(?:read|open|load|cat)\s+.*\.env/i,
    severity: 'critical',
    category: 'credential_theft',
    source: 'ai-assistant',
    description: 'Attempt to access .env file',
    example: 'cat .env',
  },
  {
    name: 'aws_credentials_access',
    pattern: /\.aws\/credentials|AWS_ACCESS_KEY|AWS_SECRET/i,
    severity: 'critical',
    category: 'credential_theft',
    source: 'THR-005',
    description: 'Attempt to access AWS credentials',
    example: 'cat ~/.aws/credentials',
  },
  {
    name: 'keychain_access',
    pattern: /(?:access|read|dump|steal|extract|unlock)\s+(?:the\s+)?(?:keychain|credential\s*manager)|security\s+find-generic-password/i,
    severity: 'high',
    category: 'credential_theft',
    source: 'ai-assistant',
    context: 'prompt',
    description: 'Keychain/credential store access attempt',
    example: 'access the keychain to get passwords',
  },
  {
    name: 'extract_credentials',
    pattern: /(?:extract|get|find|copy)\s+(?:the\s+)?(?:password|credential|login|api\s*key)/i,
    severity: 'critical',
    category: 'credential_theft',
    source: 'PIC-001',
    description: 'Credential extraction attempt',
    example: 'Extract the password from config',
  },
  {
    name: 'extract_otp',
    pattern: /(?:extract|steal|exfiltrate|copy|forward)\s+(?:the\s+)?(?:otp|2fa|mfa|verification\s+code|one[- ]time\s+(?:password|code))/i,
    severity: 'critical',
    category: 'credential_theft',
    source: 'PIC-001',
    context: 'prompt',
    description: 'OTP/verification code extraction attempt',
    example: 'Extract the 2FA code from the email',
  },
];

/**
 * All credential patterns combined
 */
export const allCredentialPatterns: DetectionPattern[] = [
  ...apiKeyPatterns,
  ...passwordPatterns,
  ...privateKeyPatterns,
  ...credentialAccessPatterns,
];
