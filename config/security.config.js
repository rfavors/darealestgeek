/**
 * Security Configuration for daRealestGeek Platform
 * 
 * This file contains all security-related configurations including:
 * - Authentication settings
 * - Rate limiting configurations
 * - Input validation rules
 * - Encryption settings
 * - Audit logging configuration
 * - IP whitelisting/blacklisting
 * - Security headers
 * - File upload restrictions
 */

const path = require('path');
const crypto = require('crypto');

// Environment-specific configurations
const environments = {
  development: {
    // More lenient settings for development
    rateLimit: {
      short: { ttl: 60000, limit: 100 },
      medium: { ttl: 900000, limit: 500 },
      long: { ttl: 3600000, limit: 2000 },
    },
    security: {
      enableHttps: false,
      strictCors: false,
      enableCSP: false,
      logLevel: 'debug',
    },
    audit: {
      enableFileLogging: true,
      enableDatabaseLogging: true,
      retentionDays: 30,
    },
  },
  staging: {
    // Production-like settings for staging
    rateLimit: {
      short: { ttl: 60000, limit: 50 },
      medium: { ttl: 900000, limit: 200 },
      long: { ttl: 3600000, limit: 1000 },
    },
    security: {
      enableHttps: true,
      strictCors: true,
      enableCSP: true,
      logLevel: 'info',
    },
    audit: {
      enableFileLogging: true,
      enableDatabaseLogging: true,
      retentionDays: 90,
    },
  },
  production: {
    // Strict settings for production
    rateLimit: {
      short: { ttl: 60000, limit: 30 },
      medium: { ttl: 900000, limit: 100 },
      long: { ttl: 3600000, limit: 500 },
    },
    security: {
      enableHttps: true,
      strictCors: true,
      enableCSP: true,
      logLevel: 'warn',
    },
    audit: {
      enableFileLogging: true,
      enableDatabaseLogging: true,
      retentionDays: 365,
    },
  },
};

// Base security configuration
const baseConfig = {
  // JWT Configuration
  jwt: {
    secret: process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex'),
    expiresIn: process.env.JWT_EXPIRES_IN || '24h',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
    issuer: process.env.JWT_ISSUER || 'daRealestGeek',
    audience: process.env.JWT_AUDIENCE || 'daRealestGeek-users',
    algorithm: 'HS256',
  },

  // Encryption Configuration
  encryption: {
    algorithm: 'aes-256-gcm',
    keyLength: 32,
    ivLength: 16,
    tagLength: 16,
    key: process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex'),
    saltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12,
  },

  // Session Configuration
  session: {
    secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
    name: 'daRealestGeek.sid',
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'strict',
  },

  // CORS Configuration
  cors: {
    origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',') : [
      'http://localhost:3000',
      'http://localhost:3001',
      'https://darealestgeek.com',
      'https://www.darealestgeek.com',
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
      'Origin',
      'X-Requested-With',
      'Content-Type',
      'Accept',
      'Authorization',
      'X-CSRF-Token',
      'X-API-Key',
    ],
    exposedHeaders: ['X-Total-Count', 'X-Rate-Limit-Remaining'],
    maxAge: 86400, // 24 hours
  },

  // Security Headers Configuration
  securityHeaders: {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:', 'https:'],
        scriptSrc: ["'self'"],
        connectSrc: ["'self'"],
        frameSrc: ["'none'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    hsts: {
      maxAge: 31536000, // 1 year
      includeSubDomains: true,
      preload: true,
    },
    noSniff: true,
    frameguard: { action: 'deny' },
    xssFilter: true,
    referrerPolicy: 'strict-origin-when-cross-origin',
  },

  // Input Validation Configuration
  validation: {
    maxStringLength: 10000,
    maxArrayLength: 1000,
    maxObjectDepth: 10,
    allowedFileTypes: [
      'image/jpeg',
      'image/png',
      'image/gif',
      'image/webp',
      'application/pdf',
      'text/plain',
      'text/csv',
      'application/json',
    ],
    maxFileSize: 10 * 1024 * 1024, // 10MB
    maxFiles: 10,
  },

  // IP Management Configuration
  ipManagement: {
    whitelist: process.env.IP_WHITELIST ? process.env.IP_WHITELIST.split(',') : [],
    blacklist: process.env.IP_BLACKLIST ? process.env.IP_BLACKLIST.split(',') : [],
    autoBlockThreshold: {
      failedAttempts: 10,
      timeWindow: 15 * 60 * 1000, // 15 minutes
      blockDuration: 60 * 60 * 1000, // 1 hour
    },
    trustedProxies: [
      '127.0.0.1',
      '::1',
      '10.0.0.0/8',
      '172.16.0.0/12',
      '192.168.0.0/16',
    ],
  },

  // Audit Logging Configuration
  auditLogging: {
    enableFileLogging: process.env.AUDIT_FILE_LOGGING !== 'false',
    enableDatabaseLogging: process.env.AUDIT_DB_LOGGING !== 'false',
    logDirectory: process.env.AUDIT_LOG_DIR || path.join(process.cwd(), 'logs'),
    maxFileSize: process.env.AUDIT_MAX_FILE_SIZE || '100MB',
    maxFiles: process.env.AUDIT_MAX_FILES || '30',
    retentionDays: parseInt(process.env.AUDIT_RETENTION_DAYS) || 90,
    batchSize: 100,
    flushInterval: 5000, // 5 seconds
    sensitiveFields: [
      'password',
      'token',
      'secret',
      'key',
      'authorization',
      'cookie',
      'session',
    ],
    excludePaths: [
      '/health',
      '/metrics',
      '/favicon.ico',
      '/robots.txt',
    ],
  },

  // API Security Configuration
  api: {
    keyLength: 32,
    keyPrefix: 'drg_',
    keyExpiration: 365 * 24 * 60 * 60 * 1000, // 1 year
    maxRequestSize: '10mb',
    timeout: 30000, // 30 seconds
    enableApiVersioning: true,
    defaultVersion: 'v1',
  },

  // Password Policy Configuration
  passwordPolicy: {
    minLength: 8,
    maxLength: 128,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    preventCommonPasswords: true,
    preventUserInfoInPassword: true,
    maxConsecutiveChars: 3,
    historyCount: 5, // Remember last 5 passwords
  },

  // Two-Factor Authentication Configuration
  twoFactor: {
    issuer: 'daRealestGeek',
    window: 2, // Allow 2 time steps before/after current
    step: 30, // 30 second time step
    digits: 6, // 6 digit codes
    algorithm: 'sha1',
    backupCodeCount: 10,
    backupCodeLength: 8,
  },

  // Monitoring Configuration
  monitoring: {
    enableRealTimeAlerts: process.env.ENABLE_REAL_TIME_ALERTS !== 'false',
    alertWebhook: process.env.ALERT_WEBHOOK_URL,
    alertEmail: process.env.ALERT_EMAIL,
    checkInterval: process.env.MONITORING_INTERVAL || '*/5 * * * *', // Every 5 minutes
    thresholds: {
      failedLogins: {
        perMinute: 10,
        perHour: 50,
        perDay: 200,
      },
      injectionAttempts: {
        perMinute: 5,
        perHour: 20,
        perDay: 100,
      },
      rateLimitHits: {
        perMinute: 20,
        perHour: 100,
      },
      suspiciousIPs: {
        uniqueFailures: 5,
        timeWindow: 300000, // 5 minutes
      },
    },
  },

  // Prompt Injection Protection Configuration
  promptInjection: {
    enabled: true,
    strictMode: process.env.NODE_ENV === 'production',
    maxSuspiciousKeywords: 5,
    maxSpecialCharRatio: 0.3,
    suspiciousPatterns: [
      // Role manipulation
      /(?:you are|act as|pretend to be|roleplay as)\s+(?:a|an)?\s*(?:admin|administrator|root|system|ai|assistant|chatbot)/i,
      /(?:ignore|forget|disregard)\s+(?:previous|all|your)\s+(?:instructions|rules|guidelines)/i,
      
      // System prompt extraction
      /(?:show|display|print|reveal|tell me)\s+(?:your|the)\s+(?:system prompt|instructions|rules|guidelines)/i,
      /what\s+(?:are|were)\s+your\s+(?:original|initial)\s+(?:instructions|prompts)/i,
      
      // Jailbreak attempts
      /(?:DAN|developer mode|god mode|admin mode|debug mode)/i,
      /(?:break|bypass|override|circumvent)\s+(?:safety|security|restrictions)/i,
      
      // Code injection
      /<script[^>]*>.*?<\/script>/i,
      /javascript:\s*[^\s]/i,
      /on(?:load|click|error|focus)\s*=/i,
    ],
    suspiciousKeywords: [
      'system', 'admin', 'root', 'sudo', 'exec', 'eval', 'function',
      'script', 'alert', 'prompt', 'confirm', 'document', 'window',
      'ignore', 'forget', 'disregard', 'override', 'bypass', 'jailbreak',
    ],
  },

  // SQL Injection Protection Configuration
  sqlInjection: {
    enabled: true,
    strictMode: process.env.NODE_ENV === 'production',
    suspiciousPatterns: [
      // Union-based injection
      /\bunion\s+(?:all\s+)?select\b/i,
      /\bselect\s+.*\bfrom\s+.*\bunion\b/i,
      
      // Boolean-based blind injection
      /\b(?:and|or)\s+\d+\s*=\s*\d+/i,
      /\b(?:and|or)\s+['"]\w+['"]\s*=\s*['"]\w+['"]/i,
      
      // Time-based blind injection
      /\bwaitfor\s+delay\b/i,
      /\bsleep\s*\(/i,
      /\bbenchmark\s*\(/i,
      
      // Error-based injection
      /\bextractvalue\s*\(/i,
      /\bupdatexml\s*\(/i,
      /\bexp\s*\(\s*~\s*\(/i,
      
      // Stacked queries
      /;\s*(?:drop|delete|insert|update|create|alter)\b/i,
      /;\s*exec\s*\(/i,
      
      // Comment-based injection
      /\/\*.*?\*\//,
      /--[^\r\n]*/,
      /#[^\r\n]*/,
    ],
  },
};

// Get environment-specific configuration
function getEnvironmentConfig() {
  const env = process.env.NODE_ENV || 'development';
  return environments[env] || environments.development;
}

// Merge base config with environment-specific config
function getSecurityConfig() {
  const envConfig = getEnvironmentConfig();
  
  return {
    ...baseConfig,
    ...envConfig,
    // Deep merge rate limiting
    rateLimit: {
      ...baseConfig.rateLimit,
      ...envConfig.rateLimit,
    },
    // Deep merge security settings
    security: {
      ...baseConfig.security,
      ...envConfig.security,
    },
    // Deep merge audit settings
    audit: {
      ...baseConfig.auditLogging,
      ...envConfig.audit,
    },
  };
}

// Validate configuration
function validateConfig(config) {
  const errors = [];
  
  // Validate JWT secret
  if (!config.jwt.secret || config.jwt.secret.length < 32) {
    errors.push('JWT secret must be at least 32 characters long');
  }
  
  // Validate encryption key
  if (!config.encryption.key || config.encryption.key.length < 64) {
    errors.push('Encryption key must be at least 64 characters long');
  }
  
  // Validate session secret
  if (!config.session.secret || config.session.secret.length < 32) {
    errors.push('Session secret must be at least 32 characters long');
  }
  
  // Validate CORS origins
  if (!Array.isArray(config.cors.origin) || config.cors.origin.length === 0) {
    errors.push('CORS origins must be a non-empty array');
  }
  
  // Validate rate limits
  if (!config.rateLimit.short.limit || config.rateLimit.short.limit < 1) {
    errors.push('Rate limit must be at least 1');
  }
  
  if (errors.length > 0) {
    throw new Error(`Security configuration validation failed:\n${errors.join('\n')}`);
  }
  
  return true;
}

// Generate secure random values for missing secrets
function generateSecrets() {
  const secrets = {};
  
  if (!process.env.JWT_SECRET) {
    secrets.JWT_SECRET = crypto.randomBytes(64).toString('hex');
  }
  
  if (!process.env.ENCRYPTION_KEY) {
    secrets.ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
  }
  
  if (!process.env.SESSION_SECRET) {
    secrets.SESSION_SECRET = crypto.randomBytes(64).toString('hex');
  }
  
  return secrets;
}

// Export configuration
module.exports = {
  getSecurityConfig,
  validateConfig,
  generateSecrets,
  environments,
  baseConfig,
};

// Auto-validate configuration on load
if (require.main !== module) {
  try {
    const config = getSecurityConfig();
    validateConfig(config);
  } catch (error) {
    console.error('Security configuration error:', error.message);
    
    // In development, show helpful message about generating secrets
    if (process.env.NODE_ENV === 'development') {
      const secrets = generateSecrets();
      if (Object.keys(secrets).length > 0) {
        console.log('\nGenerated secrets for development (add to .env file):');
        Object.entries(secrets).forEach(([key, value]) => {
          console.log(`${key}=${value}`);
        });
      }
    }
    
    if (process.env.NODE_ENV === 'production') {
      process.exit(1);
    }
  }
}