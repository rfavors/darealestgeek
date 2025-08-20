/**
 * Prompt Injection Protection Guard
 * Protects against prompt injection attacks in AI-powered features
 */

import { Injectable, CanActivate, ExecutionContext, BadRequestException } from '@nestjs/common';
import { Request } from 'express';
import { ConfigService } from '@nestjs/config';
import { Logger } from '@nestjs/common';

@Injectable()
export class PromptInjectionGuard implements CanActivate {
  private readonly logger = new Logger(PromptInjectionGuard.name);
  
  // Common prompt injection patterns
  private readonly suspiciousPatterns = [
    // Direct instruction attempts
    /ignore\s+(previous|above|all)\s+(instructions?|prompts?|rules?)/gi,
    /forget\s+(everything|all|previous|above)/gi,
    /disregard\s+(previous|above|all)\s+(instructions?|prompts?|rules?)/gi,
    
    // Role manipulation
    /you\s+are\s+(now|a|an)\s+(assistant|ai|bot|system|admin|developer)/gi,
    /act\s+as\s+(if\s+you\s+are\s+)?(a|an)?\s*(assistant|ai|bot|system|admin|developer)/gi,
    /pretend\s+(to\s+be|you\s+are)\s+(a|an)?\s*(assistant|ai|bot|system|admin|developer)/gi,
    
    // System prompt extraction
    /show\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions?|rules?)/gi,
    /what\s+(are\s+)?(your|the)\s+(system\s+)?(prompt|instructions?|rules?)/gi,
    /reveal\s+(your|the)\s+(system\s+)?(prompt|instructions?|rules?)/gi,
    
    // Jailbreak attempts
    /\[\s*system\s*\]/gi,
    /\[\s*user\s*\]/gi,
    /\[\s*assistant\s*\]/gi,
    /<\s*system\s*>/gi,
    /<\s*user\s*>/gi,
    /<\s*assistant\s*>/gi,
    
    // Code injection in prompts
    /```\s*(python|javascript|js|bash|sh|sql|php)/gi,
    /exec\s*\(/gi,
    /eval\s*\(/gi,
    /system\s*\(/gi,
    
    // Prompt termination attempts
    /\-\-\-+/g,
    /===+/g,
    /####+/g,
    
    // Unicode and encoding attacks
    /\\u[0-9a-fA-F]{4}/g,
    /\\x[0-9a-fA-F]{2}/g,
    /%[0-9a-fA-F]{2}/g,
    
    // SQL injection patterns in prompts
    /union\s+select/gi,
    /drop\s+table/gi,
    /delete\s+from/gi,
    /insert\s+into/gi,
    /update\s+set/gi,
    
    // XSS patterns in prompts
    /<script[^>]*>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
    
    // Data exfiltration attempts
    /show\s+(me\s+)?(all\s+)?(users?|passwords?|keys?|secrets?|tokens?)/gi,
    /list\s+(all\s+)?(users?|passwords?|keys?|secrets?|tokens?)/gi,
    /get\s+(all\s+)?(users?|passwords?|keys?|secrets?|tokens?)/gi,
  ];
  
  // Suspicious keywords that might indicate injection attempts
  private readonly suspiciousKeywords = [
    'ignore', 'forget', 'disregard', 'override', 'bypass', 'jailbreak',
    'system', 'admin', 'root', 'sudo', 'execute', 'eval', 'exec',
    'prompt', 'instruction', 'rule', 'guideline', 'constraint',
    'developer', 'openai', 'anthropic', 'claude', 'gpt', 'chatgpt',
    'assistant', 'ai', 'bot', 'model', 'neural', 'network',
    'token', 'secret', 'key', 'password', 'credential', 'auth',
    'database', 'sql', 'query', 'table', 'schema', 'drop', 'delete',
    'script', 'javascript', 'python', 'bash', 'shell', 'command'
  ];
  
  constructor(private configService: ConfigService) {}
  
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    
    // Skip validation in development if configured
    if (this.configService.get('NODE_ENV') === 'development' && 
        this.configService.get('SKIP_PROMPT_INJECTION_GUARD') === 'true') {
      return true;
    }
    
    try {
      // Check all text inputs in the request
      const textInputs = this.extractTextInputs(request);
      
      for (const input of textInputs) {
        if (this.detectPromptInjection(input)) {
          this.logger.warn('Prompt injection attempt detected', {
            ip: request.ip,
            userAgent: request.get('User-Agent'),
            path: request.path,
            method: request.method,
            suspiciousInput: this.sanitizeForLogging(input)
          });
          
          throw new BadRequestException({
            message: 'Invalid input detected. Please review your request and try again.',
            code: 'INVALID_INPUT',
            timestamp: new Date().toISOString()
          });
        }
      }
      
      return true;
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      
      this.logger.error('Error in prompt injection guard', error);
      // Fail securely - block the request if we can't validate it
      throw new BadRequestException('Request validation failed');
    }
  }
  
  private extractTextInputs(request: Request): string[] {
    const inputs: string[] = [];
    
    // Extract from body
    if (request.body && typeof request.body === 'object') {
      this.extractTextFromObject(request.body, inputs);
    }
    
    // Extract from query parameters
    if (request.query && typeof request.query === 'object') {
      this.extractTextFromObject(request.query, inputs);
    }
    
    // Extract from URL parameters
    if (request.params && typeof request.params === 'object') {
      this.extractTextFromObject(request.params, inputs);
    }
    
    return inputs;
  }
  
  private extractTextFromObject(obj: any, inputs: string[], depth = 0): void {
    // Prevent infinite recursion
    if (depth > 10) return;
    
    for (const [key, value] of Object.entries(obj)) {
      if (typeof value === 'string' && value.length > 0) {
        inputs.push(value);
      } else if (typeof value === 'object' && value !== null) {
        this.extractTextFromObject(value, inputs, depth + 1);
      }
    }
  }
  
  private detectPromptInjection(input: string): boolean {
    if (!input || typeof input !== 'string') {
      return false;
    }
    
    // Normalize input for analysis
    const normalizedInput = this.normalizeInput(input);
    
    // Check against suspicious patterns
    for (const pattern of this.suspiciousPatterns) {
      if (pattern.test(normalizedInput)) {
        return true;
      }
    }
    
    // Check for high concentration of suspicious keywords
    const suspiciousKeywordCount = this.countSuspiciousKeywords(normalizedInput);
    const wordCount = normalizedInput.split(/\s+/).length;
    const suspiciousRatio = suspiciousKeywordCount / Math.max(wordCount, 1);
    
    // If more than 20% of words are suspicious, flag as potential injection
    if (suspiciousRatio > 0.2 && suspiciousKeywordCount >= 3) {
      return true;
    }
    
    // Check for encoding attempts
    if (this.hasEncodingAttempts(normalizedInput)) {
      return true;
    }
    
    // Check for excessive special characters (potential obfuscation)
    if (this.hasExcessiveSpecialChars(normalizedInput)) {
      return true;
    }
    
    return false;
  }
  
  private normalizeInput(input: string): string {
    return input
      .toLowerCase()
      .replace(/[\r\n\t]+/g, ' ') // Replace line breaks and tabs with spaces
      .replace(/\s+/g, ' ') // Normalize whitespace
      .trim();
  }
  
  private countSuspiciousKeywords(input: string): number {
    let count = 0;
    const words = input.split(/\s+/);
    
    for (const word of words) {
      const cleanWord = word.replace(/[^a-z0-9]/g, '');
      if (this.suspiciousKeywords.includes(cleanWord)) {
        count++;
      }
    }
    
    return count;
  }
  
  private hasEncodingAttempts(input: string): boolean {
    // Check for various encoding attempts
    const encodingPatterns = [
      /\\u[0-9a-fA-F]{4}/, // Unicode escape
      /\\x[0-9a-fA-F]{2}/, // Hex escape
      /%[0-9a-fA-F]{2}/, // URL encoding
      /&#\d+;/, // HTML entity (decimal)
      /&#x[0-9a-fA-F]+;/, // HTML entity (hex)
      /\\[0-7]{1,3}/, // Octal escape
    ];
    
    return encodingPatterns.some(pattern => pattern.test(input));
  }
  
  private hasExcessiveSpecialChars(input: string): boolean {
    const specialCharCount = (input.match(/[^a-zA-Z0-9\s]/g) || []).length;
    const totalLength = input.length;
    
    // If more than 30% of characters are special characters, it might be obfuscation
    return totalLength > 10 && (specialCharCount / totalLength) > 0.3;
  }
  
  private sanitizeForLogging(input: string): string {
    // Truncate and sanitize input for safe logging
    const maxLength = 200;
    const truncated = input.length > maxLength ? input.substring(0, maxLength) + '...' : input;
    
    // Remove potential sensitive information
    return truncated
      .replace(/password[^\s]*\s*[=:]\s*[^\s]+/gi, 'password=***')
      .replace(/token[^\s]*\s*[=:]\s*[^\s]+/gi, 'token=***')
      .replace(/key[^\s]*\s*[=:]\s*[^\s]+/gi, 'key=***')
      .replace(/secret[^\s]*\s*[=:]\s*[^\s]+/gi, 'secret=***');
  }
}

/**
 * Decorator to apply prompt injection protection to specific routes
 */
export const PromptInjectionProtection = () => {
  return (target: any, propertyName: string, descriptor: PropertyDescriptor) => {
    // This decorator can be used to mark specific endpoints for protection
    Reflect.defineMetadata('prompt-injection-protection', true, descriptor.value);
  };
};