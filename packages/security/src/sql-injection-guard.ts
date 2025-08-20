/**
 * SQL Injection Protection Guard
 * Provides comprehensive protection against SQL injection attacks
 */

import { Injectable, CanActivate, ExecutionContext, BadRequestException } from '@nestjs/common';
import { Request } from 'express';
import { ConfigService } from '@nestjs/config';
import { Logger } from '@nestjs/common';

@Injectable()
export class SqlInjectionGuard implements CanActivate {
  private readonly logger = new Logger(SqlInjectionGuard.name);
  
  // SQL injection patterns
  private readonly sqlInjectionPatterns = [
    // Union-based injection
    /\bunion\s+(all\s+)?select\b/gi,
    /\bunion\s+(all\s+)?\(\s*select\b/gi,
    
    // Boolean-based blind injection
    /\b(and|or)\s+\d+\s*=\s*\d+/gi,
    /\b(and|or)\s+['"]\w+['"]\s*=\s*['"]\w+['"]/gi,
    /\b(and|or)\s+\d+\s*(>|<|>=|<=)\s*\d+/gi,
    
    // Time-based blind injection
    /\bwaitfor\s+delay\b/gi,
    /\bsleep\s*\(/gi,
    /\bbenchmark\s*\(/gi,
    /\bpg_sleep\s*\(/gi,
    
    // Error-based injection
    /\bextractvalue\s*\(/gi,
    /\bupdatexml\s*\(/gi,
    /\bexp\s*\(\s*~\s*\(/gi,
    
    // Stacked queries
    /;\s*(drop|delete|insert|update|create|alter|exec|execute)\b/gi,
    /;\s*--/g,
    /;\s*\/\*/g,
    
    // Comment-based injection
    /\/\*.*?\*\//gs,
    /--[^\r\n]*/g,
    /#[^\r\n]*/g,
    
    // Database-specific functions
    /\b(concat|group_concat|string_agg)\s*\(/gi,
    /\b(version|user|database|schema)\s*\(\s*\)/gi,
    /\b@@(version|user|hostname)/gi,
    /\binformation_schema\./gi,
    /\bsys\./gi,
    /\bmaster\./gi,
    
    // Subquery injection
    /\(\s*select\b/gi,
    /\bexists\s*\(\s*select\b/gi,
    
    // Data manipulation
    /\b(drop|delete|insert|update|create|alter|truncate)\s+(table|database|schema|index|view)/gi,
    /\binto\s+(outfile|dumpfile)/gi,
    /\bload_file\s*\(/gi,
    
    // Privilege escalation
    /\bgrant\s+(all|select|insert|update|delete)/gi,
    /\brevoke\s+(all|select|insert|update|delete)/gi,
    
    // Stored procedures and functions
    /\b(exec|execute|sp_|xp_)\w*/gi,
    /\bcall\s+\w+\s*\(/gi,
    
    // Hex and char-based injection
    /\b0x[0-9a-fA-F]+/g,
    /\bchar\s*\(\s*\d+/gi,
    /\bascii\s*\(/gi,
    
    // Conditional statements
    /\bif\s*\(.*?,.*?,.*?\)/gi,
    /\bcase\s+when\b/gi,
    /\biif\s*\(/gi,
    
    // Database fingerprinting
    /\b(mysql|postgresql|oracle|mssql|sqlite)\b/gi,
    /\bpg_/gi,
    /\bmysql_/gi,
    
    // Encoding attempts
    /\bconvert\s*\(/gi,
    /\bcast\s*\(/gi,
    /\bunhex\s*\(/gi,
    
    // File operations
    /\bselect\s+.*\binto\s+(outfile|dumpfile)/gi,
    /\bload\s+data\s+(local\s+)?infile/gi,
  ];
  
  // SQL keywords that are suspicious in user input
  private readonly suspiciousSqlKeywords = [
    'select', 'insert', 'update', 'delete', 'drop', 'create', 'alter',
    'union', 'join', 'where', 'having', 'group', 'order', 'limit',
    'exec', 'execute', 'sp_', 'xp_', 'waitfor', 'delay', 'sleep',
    'benchmark', 'extractvalue', 'updatexml', 'concat', 'version',
    'user', 'database', 'schema', 'table', 'column', 'index',
    'grant', 'revoke', 'commit', 'rollback', 'transaction',
    'information_schema', 'sys', 'master', 'mysql', 'postgresql',
    'oracle', 'mssql', 'sqlite', 'pg_', 'mysql_'
  ];
  
  // Characters commonly used in SQL injection
  private readonly suspiciousCharacters = [
    "'", '"', ';', '--', '/*', '*/', '#', '@@', '0x'
  ];
  
  constructor(private configService: ConfigService) {}
  
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    
    // Skip validation in development if configured
    if (this.configService.get('NODE_ENV') === 'development' && 
        this.configService.get('SKIP_SQL_INJECTION_GUARD') === 'true') {
      return true;
    }
    
    try {
      // Check all inputs in the request
      const allInputs = this.extractAllInputs(request);
      
      for (const input of allInputs) {
        if (this.detectSqlInjection(input)) {
          this.logger.warn('SQL injection attempt detected', {
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
      
      this.logger.error('Error in SQL injection guard', error);
      // Fail securely - block the request if we can't validate it
      throw new BadRequestException('Request validation failed');
    }
  }
  
  private extractAllInputs(request: Request): string[] {
    const inputs: string[] = [];
    
    // Extract from body
    if (request.body && typeof request.body === 'object') {
      this.extractStringsFromObject(request.body, inputs);
    }
    
    // Extract from query parameters
    if (request.query && typeof request.query === 'object') {
      this.extractStringsFromObject(request.query, inputs);
    }
    
    // Extract from URL parameters
    if (request.params && typeof request.params === 'object') {
      this.extractStringsFromObject(request.params, inputs);
    }
    
    // Extract from headers (specific ones that might contain user input)
    const userInputHeaders = ['x-search-query', 'x-filter', 'x-sort'];
    for (const header of userInputHeaders) {
      const value = request.get(header);
      if (value) {
        inputs.push(value);
      }
    }
    
    return inputs;
  }
  
  private extractStringsFromObject(obj: any, inputs: string[], depth = 0): void {
    // Prevent infinite recursion
    if (depth > 10) return;
    
    for (const [key, value] of Object.entries(obj)) {
      if (typeof value === 'string' && value.length > 0) {
        inputs.push(value);
      } else if (typeof value === 'number') {
        inputs.push(value.toString());
      } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        this.extractStringsFromObject(value, inputs, depth + 1);
      } else if (Array.isArray(value)) {
        for (const item of value) {
          if (typeof item === 'string') {
            inputs.push(item);
          } else if (typeof item === 'number') {
            inputs.push(item.toString());
          } else if (typeof item === 'object' && item !== null) {
            this.extractStringsFromObject(item, inputs, depth + 1);
          }
        }
      }
    }
  }
  
  private detectSqlInjection(input: string): boolean {
    if (!input || typeof input !== 'string') {
      return false;
    }
    
    // Normalize input for analysis
    const normalizedInput = this.normalizeInput(input);
    
    // Check against SQL injection patterns
    for (const pattern of this.sqlInjectionPatterns) {
      if (pattern.test(normalizedInput)) {
        return true;
      }
    }
    
    // Check for suspicious character combinations
    if (this.hasSuspiciousCharacterCombinations(normalizedInput)) {
      return true;
    }
    
    // Check for high concentration of SQL keywords
    const sqlKeywordCount = this.countSqlKeywords(normalizedInput);
    const wordCount = normalizedInput.split(/\s+/).length;
    const sqlRatio = sqlKeywordCount / Math.max(wordCount, 1);
    
    // If more than 30% of words are SQL keywords, flag as potential injection
    if (sqlRatio > 0.3 && sqlKeywordCount >= 2) {
      return true;
    }
    
    // Check for encoded SQL injection attempts
    if (this.hasEncodedSqlInjection(normalizedInput)) {
      return true;
    }
    
    return false;
  }
  
  private normalizeInput(input: string): string {
    return input
      .toLowerCase()
      .replace(/[\r\n\t]+/g, ' ') // Replace line breaks and tabs with spaces
      .replace(/\s+/g, ' ') // Normalize whitespace
      .replace(/\/\*.*?\*\//g, ' ') // Remove SQL comments
      .replace(/--.*$/gm, ' ') // Remove SQL line comments
      .replace(/#.*$/gm, ' ') // Remove MySQL comments
      .trim();
  }
  
  private hasSuspiciousCharacterCombinations(input: string): boolean {
    // Check for common SQL injection character patterns
    const suspiciousPatterns = [
      /['"]+\s*(or|and)\s*['"]*\s*\d+\s*[=<>]/gi,
      /['"]+\s*(or|and)\s*['"]+/gi,
      /\d+\s*[=<>]\s*\d+/g,
      /['"]+\s*;/g,
      /;\s*['"]/g,
      /\)\s*(and|or)\s*\(/gi,
      /\bor\s+1\s*=\s*1\b/gi,
      /\band\s+1\s*=\s*1\b/gi,
      /\bor\s+true\b/gi,
      /\band\s+false\b/gi,
    ];
    
    return suspiciousPatterns.some(pattern => pattern.test(input));
  }
  
  private countSqlKeywords(input: string): number {
    let count = 0;
    const words = input.split(/\s+/);
    
    for (const word of words) {
      const cleanWord = word.replace(/[^a-z0-9_]/g, '');
      if (this.suspiciousSqlKeywords.includes(cleanWord)) {
        count++;
      }
    }
    
    return count;
  }
  
  private hasEncodedSqlInjection(input: string): boolean {
    // Check for URL-encoded SQL injection attempts
    try {
      const decoded = decodeURIComponent(input);
      if (decoded !== input) {
        // If the input was URL-encoded, check the decoded version
        return this.detectSqlInjection(decoded);
      }
    } catch (error) {
      // Invalid URL encoding, might be an attack
      return true;
    }
    
    // Check for hex-encoded SQL injection
    const hexPattern = /0x[0-9a-fA-F]+/g;
    const hexMatches = input.match(hexPattern);
    if (hexMatches) {
      for (const hexMatch of hexMatches) {
        try {
          const hexValue = hexMatch.substring(2);
          const decoded = Buffer.from(hexValue, 'hex').toString('ascii');
          if (this.detectSqlInjection(decoded)) {
            return true;
          }
        } catch (error) {
          // Invalid hex encoding, might be an attack
          return true;
        }
      }
    }
    
    return false;
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
 * Input sanitizer for additional protection
 */
export class InputSanitizer {
  /**
   * Sanitize string input to prevent SQL injection
   */
  static sanitizeString(input: string): string {
    if (!input || typeof input !== 'string') {
      return '';
    }
    
    return input
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // Remove control characters
      .replace(/'/g, "''") // Escape single quotes
      .replace(/"/g, '""') // Escape double quotes
      .replace(/\\/g, '\\\\') // Escape backslashes
      .trim();
  }
  
  /**
   * Sanitize numeric input
   */
  static sanitizeNumber(input: any): number | null {
    if (typeof input === 'number' && !isNaN(input) && isFinite(input)) {
      return input;
    }
    
    if (typeof input === 'string') {
      const parsed = parseFloat(input);
      if (!isNaN(parsed) && isFinite(parsed)) {
        return parsed;
      }
    }
    
    return null;
  }
  
  /**
   * Sanitize boolean input
   */
  static sanitizeBoolean(input: any): boolean {
    if (typeof input === 'boolean') {
      return input;
    }
    
    if (typeof input === 'string') {
      const lower = input.toLowerCase().trim();
      return lower === 'true' || lower === '1' || lower === 'yes';
    }
    
    if (typeof input === 'number') {
      return input !== 0;
    }
    
    return false;
  }
  
  /**
   * Validate and sanitize email input
   */
  static sanitizeEmail(input: string): string | null {
    if (!input || typeof input !== 'string') {
      return null;
    }
    
    const sanitized = input.trim().toLowerCase();
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    
    if (emailRegex.test(sanitized) && sanitized.length <= 254) {
      return sanitized;
    }
    
    return null;
  }
}

/**
 * Decorator to apply SQL injection protection to specific routes
 */
export const SqlInjectionProtection = () => {
  return (target: any, propertyName: string, descriptor: PropertyDescriptor) => {
    // This decorator can be used to mark specific endpoints for protection
    Reflect.defineMetadata('sql-injection-protection', true, descriptor.value);
  };
};