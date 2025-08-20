/**
 * Security Package - Main Export File
 * Comprehensive security utilities for daRealestGeek platform
 */

// Guards
export { PromptInjectionGuard } from './prompt-injection-guard';
export { SqlInjectionGuard } from './sql-injection-guard';
export { PromptInjectionProtection } from './prompt-injection-guard';
export { SqlInjectionProtection } from './sql-injection-guard';

// Services
export { InputValidationService } from './input-validation.service';
export { SecurityService, SecurityContext, SecurityUtils } from './security.service';
export { AuditLogService, AuditLogEntry, AuditLogFilter, AuditLogStats } from './audit-log.service';

// Middleware & Interceptors
export { SecurityMiddleware } from './security.middleware';
export { SecurityInterceptor } from './security.interceptor';

// Module
export { SecurityModule } from './security.module';

// Types and Interfaces
export interface ValidationRule {
  type: 'string' | 'number' | 'boolean' | 'email' | 'url' | 'uuid' | 'date' | 'array' | 'object';
  required?: boolean;
  minLength?: number;
  maxLength?: number;
  min?: number;
  max?: number;
  pattern?: RegExp;
  allowedValues?: any[];
  customValidator?: (value: any) => boolean | string;
  sanitize?: boolean;
  arrayItemType?: ValidationRule;
  objectSchema?: ValidationSchema;
}

export interface ValidationSchema {
  [key: string]: ValidationRule;
}

export interface ValidationError {
  field: string;
  message: string;
  value?: any;
}

export interface ValidationResult {
  isValid: boolean;
  errors: ValidationError[];
  sanitizedData?: any;
}

// Security Configuration Types
export interface SecurityConfig {
  rateLimit: {
    windowMs: number;
    max: number;
    skipSuccessfulRequests?: boolean;
    skipFailedRequests?: boolean;
  };
  cors: {
    origin: string | string[] | boolean;
    credentials: boolean;
    methods: string[];
    allowedHeaders: string[];
  };
  helmet: {
    contentSecurityPolicy?: any;
    crossOriginEmbedderPolicy?: boolean;
    crossOriginOpenerPolicy?: boolean;
    crossOriginResourcePolicy?: any;
    dnsPrefetchControl?: boolean;
    frameguard?: any;
    hidePoweredBy?: boolean;
    hsts?: any;
    ieNoOpen?: boolean;
    noSniff?: boolean;
    originAgentCluster?: boolean;
    permittedCrossDomainPolicies?: boolean;
    referrerPolicy?: any;
    xssFilter?: boolean;
  };
  encryption: {
    algorithm: string;
    keyLength: number;
    ivLength: number;
  };
  jwt: {
    secret: string;
    expiresIn: string;
    issuer: string;
    audience: string;
  };
  password: {
    minLength: number;
    requireUppercase: boolean;
    requireLowercase: boolean;
    requireNumbers: boolean;
    requireSpecialChars: boolean;
    maxAge: number; // days
  };
  session: {
    secret: string;
    maxAge: number;
    secure: boolean;
    httpOnly: boolean;
    sameSite: 'strict' | 'lax' | 'none';
  };
  audit: {
    enabled: boolean;
    retentionDays: number;
    enableDatabaseLogging: boolean;
    enableFileLogging: boolean;
    bufferSize: number;
  };
}

// Security Event Types
export interface SecurityEvent {
  type: 'authentication' | 'authorization' | 'data_access' | 'security_violation' | 'system';
  severity: 'low' | 'medium' | 'high' | 'critical';
  action: string;
  resource: string;
  userId?: string;
  sessionId?: string;
  ip: string;
  userAgent: string;
  timestamp: Date;
  metadata?: Record<string, any>;
  success: boolean;
  errorMessage?: string;
}

// Utility Functions
export const SecurityConstants = {
  // Password requirements
  PASSWORD_MIN_LENGTH: 8,
  PASSWORD_MAX_LENGTH: 128,
  
  // Token expiration times
  ACCESS_TOKEN_EXPIRES_IN: '15m',
  REFRESH_TOKEN_EXPIRES_IN: '7d',
  RESET_TOKEN_EXPIRES_IN: '1h',
  VERIFICATION_TOKEN_EXPIRES_IN: '24h',
  
  // Rate limiting
  DEFAULT_RATE_LIMIT: 100,
  AUTH_RATE_LIMIT: 5,
  API_RATE_LIMIT: 1000,
  
  // Security headers
  SECURITY_HEADERS: {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
  },
  
  // File upload limits
  MAX_FILE_SIZE: 10 * 1024 * 1024, // 10MB
  ALLOWED_IMAGE_TYPES: ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
  ALLOWED_DOCUMENT_TYPES: [
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'text/plain',
    'text/csv',
  ],
  
  // Encryption
  ENCRYPTION_ALGORITHM: 'aes-256-gcm',
  HASH_ALGORITHM: 'sha256',
  SALT_ROUNDS: 12,
  
  // Session
  SESSION_COOKIE_NAME: 'darealestgeek.sid',
  CSRF_COOKIE_NAME: 'darealestgeek.csrf',
  
  // Audit log categories
  AUDIT_CATEGORIES: {
    AUTHENTICATION: 'authentication',
    AUTHORIZATION: 'authorization',
    DATA_ACCESS: 'data_access',
    DATA_MODIFICATION: 'data_modification',
    SYSTEM: 'system',
    SECURITY: 'security',
  },
  
  // Security event severities
  SEVERITY_LEVELS: {
    LOW: 'low',
    MEDIUM: 'medium',
    HIGH: 'high',
    CRITICAL: 'critical',
  },
} as const;

// Helper functions
export const SecurityHelpers = {
  /**
   * Check if an IP address is in a CIDR range
   */
  isIpInRange(ip: string, cidr: string): boolean {
    const [range, bits] = cidr.split('/');
    const mask = ~(2 ** (32 - parseInt(bits)) - 1);
    return (SecurityHelpers.ipToInt(ip) & mask) === (SecurityHelpers.ipToInt(range) & mask);
  },
  
  /**
   * Convert IP address to integer
   */
  ipToInt(ip: string): number {
    return ip.split('.').reduce((int, oct) => (int << 8) + parseInt(oct, 10), 0) >>> 0;
  },
  
  /**
   * Generate a secure random string
   */
  generateSecureRandom(length: number = 32): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    const randomArray = new Uint8Array(length);
    crypto.getRandomValues(randomArray);
    
    for (let i = 0; i < length; i++) {
      result += chars.charAt(randomArray[i] % chars.length);
    }
    
    return result;
  },
  
  /**
   * Validate email format
   */
  isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email) && email.length <= 254;
  },
  
  /**
   * Validate URL format
   */
  isValidUrl(url: string): boolean {
    try {
      const urlObj = new URL(url);
      return ['http:', 'https:'].includes(urlObj.protocol);
    } catch {
      return false;
    }
  },
  
  /**
   * Validate UUID format
   */
  isValidUuid(uuid: string): boolean {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
  },
  
  /**
   * Sanitize filename for safe storage
   */
  sanitizeFilename(filename: string): string {
    return filename
      .replace(/[^a-zA-Z0-9._-]/g, '_')
      .replace(/_{2,}/g, '_')
      .replace(/^_+|_+$/g, '')
      .substring(0, 255);
  },
  
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
    
    if (password.length < SecurityConstants.PASSWORD_MIN_LENGTH) {
      feedback.push(`Password must be at least ${SecurityConstants.PASSWORD_MIN_LENGTH} characters long`);
    } else {
      score += 1;
    }
    
    if (password.length > SecurityConstants.PASSWORD_MAX_LENGTH) {
      feedback.push(`Password must not exceed ${SecurityConstants.PASSWORD_MAX_LENGTH} characters`);
    }
    
    if (!/[a-z]/.test(password)) {
      feedback.push('Password must contain at least one lowercase letter');
    } else {
      score += 1;
    }
    
    if (!/[A-Z]/.test(password)) {
      feedback.push('Password must contain at least one uppercase letter');
    } else {
      score += 1;
    }
    
    if (!/\d/.test(password)) {
      feedback.push('Password must contain at least one number');
    } else {
      score += 1;
    }
    
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      feedback.push('Password must contain at least one special character');
    } else {
      score += 1;
    }
    
    // Check for common patterns
    if (/123456|password|qwerty|abc123|admin|letmein/i.test(password)) {
      feedback.push('Password contains common patterns and is not secure');
      score = Math.max(0, score - 2);
    }
    
    // Check for repeated characters
    if (/(..).*\1/.test(password)) {
      feedback.push('Password should not contain repeated patterns');
      score = Math.max(0, score - 1);
    }
    
    return {
      isValid: feedback.length === 0 && score >= 4,
      score,
      feedback,
    };
  },
  
  /**
   * Generate a secure API key
   */
  generateApiKey(prefix: string = 'sk'): string {
    const randomPart = SecurityHelpers.generateSecureRandom(32);
    return `${prefix}_${randomPart}`;
  },
  
  /**
   * Mask sensitive data for logging
   */
  maskSensitiveData(data: any): any {
    if (typeof data !== 'object' || data === null) {
      return data;
    }
    
    const sensitiveFields = [
      'password', 'token', 'secret', 'key', 'authorization',
      'cookie', 'session', 'credit_card', 'ssn', 'passport',
    ];
    
    const masked = { ...data };
    
    for (const [key, value] of Object.entries(masked)) {
      const lowerKey = key.toLowerCase();
      
      if (sensitiveFields.some(field => lowerKey.includes(field))) {
        masked[key] = '[REDACTED]';
      } else if (typeof value === 'object' && value !== null) {
        masked[key] = SecurityHelpers.maskSensitiveData(value);
      }
    }
    
    return masked;
  },
};

// Default security configuration
export const defaultSecurityConfig: Partial<SecurityConfig> = {
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: SecurityConstants.DEFAULT_RATE_LIMIT,
    skipSuccessfulRequests: false,
    skipFailedRequests: false,
  },
  cors: {
    origin: process.env.NODE_ENV === 'production' ? false : true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Origin',
      'X-Requested-With',
      'Content-Type',
      'Accept',
      'Authorization',
      'X-CSRF-Token',
    ],
  },
  helmet: {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' },
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
  },
  encryption: {
    algorithm: SecurityConstants.ENCRYPTION_ALGORITHM,
    keyLength: 32,
    ivLength: 16,
  },
  password: {
    minLength: SecurityConstants.PASSWORD_MIN_LENGTH,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    maxAge: 90, // days
  },
  audit: {
    enabled: true,
    retentionDays: 90,
    enableDatabaseLogging: true,
    enableFileLogging: false,
    bufferSize: 100,
  },
};