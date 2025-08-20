/**
 * Security Service
 * Provides centralized security operations and utilities
 */

import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createHash, createHmac, randomBytes, scrypt, timingSafeEqual } from 'crypto';
import { promisify } from 'util';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import { AuditLogService } from './audit-log.service';

const scryptAsync = promisify(scrypt);

export interface SecurityContext {
  userId?: string;
  sessionId?: string;
  ip: string;
  userAgent: string;
  timestamp: Date;
  action: string;
  resource?: string;
  metadata?: Record<string, any>;
}

export interface EncryptionResult {
  encrypted: string;
  iv: string;
  tag: string;
}

export interface HashResult {
  hash: string;
  salt: string;
}

@Injectable()
export class SecurityService {
  private readonly logger = new Logger(SecurityService.name);
  private readonly algorithm = 'aes-256-gcm';
  private readonly keyLength = 32;
  private readonly ivLength = 16;
  private readonly saltLength = 32;
  private readonly tagLength = 16;
  
  constructor(
    private configService: ConfigService,
    private auditLogService: AuditLogService
  ) {}
  
  /**
   * Hash a password using bcrypt
   */
  async hashPassword(password: string): Promise<string> {
    const saltRounds = parseInt(this.configService.get('BCRYPT_SALT_ROUNDS', '12'));
    return bcrypt.hash(password, saltRounds);
  }
  
  /**
   * Verify a password against a hash
   */
  async verifyPassword(password: string, hash: string): Promise<boolean> {
    try {
      return await bcrypt.compare(password, hash);
    } catch (error) {
      this.logger.error('Password verification error', error);
      return false;
    }
  }
  
  /**
   * Generate a secure random token
   */
  generateSecureToken(length: number = 32): string {
    return randomBytes(length).toString('hex');
  }
  
  /**
   * Generate a cryptographically secure random string
   */
  generateSecureString(length: number = 16, charset: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'): string {
    const bytes = randomBytes(length);
    const result = [];
    
    for (let i = 0; i < length; i++) {
      result.push(charset[bytes[i] % charset.length]);
    }
    
    return result.join('');
  }
  
  /**
   * Create HMAC signature
   */
  createHmacSignature(data: string, secret?: string): string {
    const hmacSecret = secret || this.configService.get('HMAC_SECRET') || 'default-secret';
    return createHmac('sha256', hmacSecret).update(data).digest('hex');
  }
  
  /**
   * Verify HMAC signature
   */
  verifyHmacSignature(data: string, signature: string, secret?: string): boolean {
    try {
      const expectedSignature = this.createHmacSignature(data, secret);
      const expectedBuffer = Buffer.from(expectedSignature, 'hex');
      const actualBuffer = Buffer.from(signature, 'hex');
      
      if (expectedBuffer.length !== actualBuffer.length) {
        return false;
      }
      
      return timingSafeEqual(expectedBuffer, actualBuffer);
    } catch (error) {
      this.logger.error('HMAC verification error', error);
      return false;
    }
  }
  
  /**
   * Encrypt sensitive data
   */
  async encryptData(data: string, key?: string): Promise<EncryptionResult> {
    try {
      const crypto = await import('crypto');
      const encryptionKey = key ? Buffer.from(key, 'hex') : await this.deriveKey();
      const iv = randomBytes(this.ivLength);
      
      const cipher = crypto.createCipher(this.algorithm, encryptionKey);
      cipher.setAAD(Buffer.from('daRealestGeek', 'utf8'));
      
      let encrypted = cipher.update(data, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      const tag = cipher.getAuthTag();
      
      return {
        encrypted,
        iv: iv.toString('hex'),
        tag: tag.toString('hex')
      };
    } catch (error) {
      this.logger.error('Encryption error', error);
      throw new Error('Encryption failed');
    }
  }
  
  /**
   * Decrypt sensitive data
   */
  async decryptData(encryptionResult: EncryptionResult, key?: string): Promise<string> {
    try {
      const crypto = await import('crypto');
      const encryptionKey = key ? Buffer.from(key, 'hex') : await this.deriveKey();
      const iv = Buffer.from(encryptionResult.iv, 'hex');
      const tag = Buffer.from(encryptionResult.tag, 'hex');
      
      const decipher = crypto.createDecipher(this.algorithm, encryptionKey);
      decipher.setAAD(Buffer.from('daRealestGeek', 'utf8'));
      decipher.setAuthTag(tag);
      
      let decrypted = decipher.update(encryptionResult.encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      this.logger.error('Decryption error', error);
      throw new Error('Decryption failed');
    }
  }
  
  /**
   * Hash data with salt using scrypt
   */
  async hashWithSalt(data: string, salt?: string): Promise<HashResult> {
    try {
      const actualSalt = salt ? Buffer.from(salt, 'hex') : randomBytes(this.saltLength);
      const hash = (await scryptAsync(data, actualSalt, this.keyLength)) as Buffer;
      
      return {
        hash: hash.toString('hex'),
        salt: actualSalt.toString('hex')
      };
    } catch (error) {
      this.logger.error('Hashing error', error);
      throw new Error('Hashing failed');
    }
  }
  
  /**
   * Verify hash with salt
   */
  async verifyHash(data: string, hashResult: HashResult): Promise<boolean> {
    try {
      const { hash: expectedHash } = await this.hashWithSalt(data, hashResult.salt);
      const expectedBuffer = Buffer.from(expectedHash, 'hex');
      const actualBuffer = Buffer.from(hashResult.hash, 'hex');
      
      if (expectedBuffer.length !== actualBuffer.length) {
        return false;
      }
      
      return timingSafeEqual(expectedBuffer, actualBuffer);
    } catch (error) {
      this.logger.error('Hash verification error', error);
      return false;
    }
  }
  
  /**
   * Generate JWT token
   */
  generateJwtToken(payload: object, expiresIn: string = '1h'): string {
    const secret = this.configService.get('JWT_SECRET');
    if (!secret) {
      throw new Error('JWT_SECRET not configured');
    }
    
    return jwt.sign(payload, secret, {
      expiresIn,
      issuer: 'daRealestGeek',
      audience: 'daRealestGeek-users'
    });
  }
  
  /**
   * Verify JWT token
   */
  verifyJwtToken(token: string): any {
    try {
      const secret = this.configService.get('JWT_SECRET');
      if (!secret) {
        throw new Error('JWT_SECRET not configured');
      }
      
      return jwt.verify(token, secret, {
        issuer: 'daRealestGeek',
        audience: 'daRealestGeek-users'
      });
    } catch (error) {
      this.logger.error('JWT verification error', error);
      return null;
    }
  }
  
  /**
   * Generate API key
   */
  generateApiKey(prefix: string = 'drg'): string {
    const timestamp = Date.now().toString(36);
    const random = this.generateSecureString(24);
    return `${prefix}_${timestamp}_${random}`;
  }
  
  /**
   * Validate API key format
   */
  validateApiKeyFormat(apiKey: string, prefix: string = 'drg'): boolean {
    const pattern = new RegExp(`^${prefix}_[a-z0-9]+_[A-Za-z0-9]{24}$`);
    return pattern.test(apiKey);
  }
  
  /**
   * Create secure session ID
   */
  createSessionId(): string {
    const timestamp = Date.now();
    const random = randomBytes(16).toString('hex');
    const hash = createHash('sha256').update(`${timestamp}-${random}`).digest('hex');
    return hash.substring(0, 32);
  }
  
  /**
   * Sanitize filename for secure file operations
   */
  sanitizeFilename(filename: string): string {
    // Remove path traversal attempts
    let sanitized = filename.replace(/\.\.\/|\.\.\\/g, '');
    
    // Remove or replace dangerous characters
    sanitized = sanitized.replace(/[<>:"|?*\x00-\x1f]/g, '_');
    
    // Limit length
    if (sanitized.length > 255) {
      const ext = sanitized.split('.').pop();
      const name = sanitized.substring(0, 255 - (ext ? ext.length + 1 : 0));
      sanitized = ext ? `${name}.${ext}` : name;
    }
    
    // Ensure it's not empty
    if (!sanitized || sanitized.trim() === '') {
      sanitized = `file_${Date.now()}`;
    }
    
    return sanitized;
  }
  
  /**
   * Generate CSRF token
   */
  generateCsrfToken(sessionId: string): string {
    const secret = this.configService.get('CSRF_SECRET', 'default-csrf-secret');
    const timestamp = Date.now().toString();
    const data = `${sessionId}-${timestamp}`;
    const signature = this.createHmacSignature(data, secret);
    return Buffer.from(`${timestamp}.${signature}`).toString('base64');
  }
  
  /**
   * Verify CSRF token
   */
  verifyCsrfToken(token: string, sessionId: string, maxAge: number = 3600000): boolean {
    try {
      const decoded = Buffer.from(token, 'base64').toString('utf8');
      const [timestamp, signature] = decoded.split('.');
      
      if (!timestamp || !signature) {
        return false;
      }
      
      // Check if token is expired
      const tokenTime = parseInt(timestamp);
      if (Date.now() - tokenTime > maxAge) {
        return false;
      }
      
      // Verify signature
      const secret = this.configService.get('CSRF_SECRET', 'default-csrf-secret');
      const data = `${sessionId}-${timestamp}`;
      return this.verifyHmacSignature(data, signature, secret);
    } catch (error) {
      this.logger.error('CSRF token verification error', error);
      return false;
    }
  }
  
  /**
   * Log security event
   */
  async logSecurityEvent(context: SecurityContext, level: 'info' | 'warn' | 'error' = 'info') {
    try {
      await this.auditLogService.log({
        userId: context.userId,
        action: context.action,
        resource: context.resource,
        ip: context.ip,
        userAgent: context.userAgent,
        metadata: {
          ...context.metadata,
          sessionId: context.sessionId,
          timestamp: context.timestamp,
          level
        }
      });
      
      const logMessage = `Security event: ${context.action} by ${context.userId || 'anonymous'} from ${context.ip}`;
      
      switch (level) {
        case 'error':
          this.logger.error(logMessage, context);
          break;
        case 'warn':
          this.logger.warn(logMessage, context);
          break;
        default:
          this.logger.log(logMessage, context);
      }
    } catch (error) {
      this.logger.error('Failed to log security event', error);
    }
  }
  
  /**
   * Derive encryption key from master secret
   */
  private async deriveKey(salt?: string): Promise<Buffer> {
    const masterSecret = this.configService.get('ENCRYPTION_SECRET', 'default-encryption-secret');
    const keySalt = salt ? Buffer.from(salt, 'hex') : Buffer.from('daRealestGeek-salt', 'utf8');
    
    return (await scryptAsync(masterSecret, keySalt, this.keyLength)) as Buffer;
  }
  
  /**
   * Check if password meets security requirements
   */
  validatePasswordStrength(password: string): {
    isValid: boolean;
    score: number;
    feedback: string[];
  } {
    const feedback: string[] = [];
    let score = 0;
    
    // Length check
    if (password.length >= 8) {
      score += 1;
    } else {
      feedback.push('Password must be at least 8 characters long');
    }
    
    if (password.length >= 12) {
      score += 1;
    }
    
    // Character variety checks
    if (/[a-z]/.test(password)) {
      score += 1;
    } else {
      feedback.push('Password must contain lowercase letters');
    }
    
    if (/[A-Z]/.test(password)) {
      score += 1;
    } else {
      feedback.push('Password must contain uppercase letters');
    }
    
    if (/\d/.test(password)) {
      score += 1;
    } else {
      feedback.push('Password must contain numbers');
    }
    
    if (/[^a-zA-Z0-9]/.test(password)) {
      score += 1;
    } else {
      feedback.push('Password must contain special characters');
    }
    
    // Common patterns check
    const commonPatterns = [
      /123456/,
      /password/i,
      /qwerty/i,
      /admin/i,
      /letmein/i,
      /(.)\1{2,}/, // Repeated characters
    ];
    
    if (commonPatterns.some(pattern => pattern.test(password))) {
      score -= 2;
      feedback.push('Password contains common patterns');
    }
    
    const isValid = score >= 4 && feedback.length === 0;
    
    return {
      isValid,
      score: Math.max(0, Math.min(6, score)),
      feedback
    };
  }
  
  /**
   * Generate secure OTP
   */
  generateOtp(length: number = 6): string {
    const digits = '0123456789';
    let otp = '';
    
    for (let i = 0; i < length; i++) {
      const randomIndex = randomBytes(1)[0] % digits.length;
      otp += digits[randomIndex];
    }
    
    return otp;
  }
  
  /**
   * Rate limiting check
   */
  private rateLimitStore = new Map<string, { count: number; resetTime: number }>();
  
  checkRateLimit(key: string, limit: number, windowMs: number): {
    allowed: boolean;
    remaining: number;
    resetTime: number;
  } {
    const now = Date.now();
    const record = this.rateLimitStore.get(key);
    
    if (!record || now > record.resetTime) {
      // Reset or create new record
      const resetTime = now + windowMs;
      this.rateLimitStore.set(key, { count: 1, resetTime });
      return {
        allowed: true,
        remaining: limit - 1,
        resetTime
      };
    }
    
    if (record.count >= limit) {
      return {
        allowed: false,
        remaining: 0,
        resetTime: record.resetTime
      };
    }
    
    record.count++;
    return {
      allowed: true,
      remaining: limit - record.count,
      resetTime: record.resetTime
    };
  }
  
  /**
   * Clean up expired rate limit records
   */
  cleanupRateLimitStore() {
    const now = Date.now();
    for (const [key, record] of this.rateLimitStore.entries()) {
      if (now > record.resetTime) {
        this.rateLimitStore.delete(key);
      }
    }
  }
}

/**
 * Security utilities
 */
export class SecurityUtils {
  /**
   * Constant-time string comparison
   */
  static constantTimeEquals(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false;
    }
    
    const bufferA = Buffer.from(a, 'utf8');
    const bufferB = Buffer.from(b, 'utf8');
    
    return timingSafeEqual(bufferA, bufferB);
  }
  
  /**
   * Mask sensitive data for logging
   */
  static maskSensitiveData(data: any, sensitiveFields: string[] = ['password', 'token', 'secret', 'key', 'apiKey']): any {
    if (typeof data !== 'object' || data === null) {
      return data;
    }
    
    const masked = { ...data };
    
    for (const field of sensitiveFields) {
      if (field in masked) {
        const value = masked[field];
        if (typeof value === 'string' && value.length > 0) {
          masked[field] = value.length > 4 
            ? `${value.substring(0, 2)}***${value.substring(value.length - 2)}`
            : '***';
        } else {
          masked[field] = '***';
        }
      }
    }
    
    return masked;
  }
  
  /**
   * Generate secure random UUID v4
   */
  static generateUuid(): string {
    const bytes = randomBytes(16);
    
    // Set version (4) and variant bits
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    
    const hex = bytes.toString('hex');
    return [
      hex.substring(0, 8),
      hex.substring(8, 12),
      hex.substring(12, 16),
      hex.substring(16, 20),
      hex.substring(20, 32)
    ].join('-');
  }
}