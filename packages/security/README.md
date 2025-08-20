# Security Package

Comprehensive security utilities and protection mechanisms for the daRealestGeek platform. This package provides robust protection against various security threats including prompt injection, SQL injection, XSS attacks, CSRF, and more.

## Features

### 🛡️ Core Security Guards
- **Prompt Injection Protection**: Advanced detection and prevention of AI prompt manipulation attacks
- **SQL Injection Protection**: Comprehensive SQL injection pattern detection and blocking
- **Input Validation**: Robust input sanitization and validation with custom rules
- **Rate Limiting**: Configurable rate limiting with multiple time windows
- **Security Headers**: Automatic security header injection using Helmet.js

### 🔐 Authentication & Authorization
- **JWT Token Management**: Secure token generation, validation, and refresh
- **Password Security**: Strong password hashing, validation, and strength checking
- **Session Management**: Secure session handling with configurable options
- **API Key Management**: Secure API key generation and validation
- **CSRF Protection**: Cross-Site Request Forgery protection

### 📊 Monitoring & Auditing
- **Security Interceptor**: Real-time request/response monitoring and logging
- **Audit Logging**: Comprehensive audit trail with categorization and severity levels
- **Security Event Tracking**: Detailed security event logging and analysis
- **Suspicious Activity Detection**: Automated detection of suspicious patterns
- **Metrics Collection**: Security metrics and statistics

### 🔒 Data Protection
- **Encryption/Decryption**: AES-256-GCM encryption for sensitive data
- **Data Sanitization**: Automatic sanitization of sensitive information in logs
- **File Upload Security**: Secure file upload validation and processing
- **IP Whitelisting/Blacklisting**: Network-level access control

## Installation

```bash
npm install @darealestgeek/security
# or
pnpm add @darealestgeek/security
```

## Quick Start

### 1. Import the Security Module

```typescript
import { Module } from '@nestjs/common';
import { SecurityModule } from '@darealestgeek/security';

@Module({
  imports: [
    SecurityModule.forRoot({
      // Security configuration
      rateLimit: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // limit each IP to 100 requests per windowMs
      },
      cors: {
        origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
        credentials: true,
      },
      // ... other configuration options
    }),
  ],
})
export class AppModule {}
```

### 2. Use Security Guards

```typescript
import { Controller, Post, UseGuards } from '@nestjs/common';
import { 
  PromptInjectionProtection, 
  SqlInjectionProtection 
} from '@darealestgeek/security';

@Controller('api')
export class ApiController {
  
  @Post('chat')
  @PromptInjectionProtection() // Protect against prompt injection
  async chat(@Body() body: ChatRequest) {
    // Your AI chat logic here
    return this.aiService.processChat(body.message);
  }
  
  @Post('search')
  @SqlInjectionProtection() // Protect against SQL injection
  async search(@Body() body: SearchRequest) {
    // Your search logic here
    return this.searchService.search(body.query);
  }
}
```

### 3. Input Validation

```typescript
import { Injectable } from '@nestjs/common';
import { InputValidationService, ValidationSchema } from '@darealestgeek/security';

@Injectable()
export class UserService {
  constructor(private validationService: InputValidationService) {}
  
  async createUser(userData: any) {
    const schema: ValidationSchema = {
      email: {
        type: 'email',
        required: true,
        sanitize: true,
      },
      password: {
        type: 'string',
        required: true,
        minLength: 8,
        pattern: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
      },
      age: {
        type: 'number',
        min: 18,
        max: 120,
      },
    };
    
    const validation = await this.validationService.validateInput(userData, schema);
    
    if (!validation.isValid) {
      throw new BadRequestException(validation.errors);
    }
    
    // Use sanitized data
    return this.createUserInDatabase(validation.sanitizedData);
  }
}
```

### 4. Security Service Usage

```typescript
import { Injectable } from '@nestjs/common';
import { SecurityService } from '@darealestgeek/security';

@Injectable()
export class AuthService {
  constructor(private securityService: SecurityService) {}
  
  async hashPassword(password: string): Promise<string> {
    return this.securityService.hashPassword(password);
  }
  
  async verifyPassword(password: string, hash: string): Promise<boolean> {
    return this.securityService.verifyPassword(password, hash);
  }
  
  async generateJWT(payload: any): Promise<string> {
    return this.securityService.generateJWT(payload);
  }
  
  async encryptSensitiveData(data: string): Promise<string> {
    return this.securityService.encrypt(data);
  }
}
```

### 5. Audit Logging

```typescript
import { Injectable } from '@nestjs/common';
import { AuditLogService } from '@darealestgeek/security';

@Injectable()
export class UserController {
  constructor(private auditLogService: AuditLogService) {}
  
  async deleteUser(userId: string, req: Request) {
    // Log the admin action
    await this.auditLogService.logAdminAction(
      req.user.id,
      'DELETE_USER',
      `user:${userId}`,
      req.ip,
      req.get('User-Agent'),
      true,
      { deletedUserId: userId }
    );
    
    // Perform the deletion
    return this.userService.deleteUser(userId);
  }
}
```

## Configuration

### Environment Variables

```env
# Security Configuration
SECURITY_JWT_SECRET=your-super-secret-jwt-key
SECURITY_ENCRYPTION_KEY=your-32-character-encryption-key
SECURITY_RATE_LIMIT_WINDOW_MS=900000
SECURITY_RATE_LIMIT_MAX=100

# Audit Logging
AUDIT_LOG_RETENTION_DAYS=90
AUDIT_LOG_DATABASE_ENABLED=true
AUDIT_LOG_FILE_ENABLED=false

# CORS
ALLOWED_ORIGINS=http://localhost:3000,https://yourdomain.com

# Session
SESSION_SECRET=your-session-secret
SESSION_MAX_AGE=86400000
```

### Security Configuration Object

```typescript
import { SecurityConfig } from '@darealestgeek/security';

const securityConfig: SecurityConfig = {
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    skipSuccessfulRequests: false,
    skipFailedRequests: false,
  },
  cors: {
    origin: ['http://localhost:3000', 'https://yourdomain.com'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  },
  helmet: {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", 'data:', 'https:'],
      },
    },
  },
  encryption: {
    algorithm: 'aes-256-gcm',
    keyLength: 32,
    ivLength: 16,
  },
  password: {
    minLength: 8,
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
```

## API Reference

### Guards

#### PromptInjectionGuard
Protects against AI prompt injection attacks.

```typescript
@UseGuards(PromptInjectionGuard)
// or use decorator
@PromptInjectionProtection()
```

#### SqlInjectionGuard
Protects against SQL injection attacks.

```typescript
@UseGuards(SqlInjectionGuard)
// or use decorator
@SqlInjectionProtection()
```

### Services

#### SecurityService
Core security utilities.

```typescript
// Password operations
hashPassword(password: string): Promise<string>
verifyPassword(password: string, hash: string): Promise<boolean>
validatePasswordStrength(password: string): PasswordStrengthResult

// Token operations
generateJWT(payload: any, expiresIn?: string): Promise<string>
verifyJWT(token: string): Promise<any>
generateSecureToken(length?: number): string

// Encryption operations
encrypt(data: string): Promise<string>
decrypt(encryptedData: string): Promise<string>

// Utility operations
generateApiKey(prefix?: string): string
maskSensitiveData(data: any): any
logSecurityEvent(context: SecurityContext, level?: string): void
```

#### InputValidationService
Input validation and sanitization.

```typescript
validateInput(data: any, schema: ValidationSchema): Promise<ValidationResult>
validateFileUpload(file: any, options?: FileUploadOptions): ValidationResult
validatePagination(page?: number, limit?: number): PaginationResult
validateSorting(sort?: string, allowedFields?: string[]): SortingResult
```

#### AuditLogService
Audit logging and compliance.

```typescript
log(entry: AuditLogEntry): Promise<void>
logAuthentication(action: string, userId: string, ip: string, userAgent: string, success: boolean): Promise<void>
logDataAccess(userId: string, action: string, resource: string, ip: string, userAgent: string): Promise<void>
logSecurityEvent(action: string, ip: string, userAgent: string, severity?: string): Promise<void>
searchLogs(filter: AuditLogFilter): Promise<AuditLogEntry[]>
getStats(startDate?: Date, endDate?: Date): Promise<AuditLogStats>
exportLogs(filter: AuditLogFilter, format?: 'json' | 'csv'): Promise<string>
```

### Middleware

#### SecurityMiddleware
Comprehensive security middleware.

```typescript
// Applied automatically when SecurityModule is imported
// Provides:
// - Rate limiting
// - Security headers
// - IP whitelisting/blacklisting
// - Request logging
// - Suspicious activity detection
```

#### SecurityInterceptor
Request/response security monitoring.

```typescript
// Applied automatically when SecurityModule is imported
// Provides:
// - Request/response logging
// - Security event detection
// - Performance monitoring
// - Error tracking
```

## Security Best Practices

### 1. Input Validation
- Always validate and sanitize user input
- Use type-safe validation schemas
- Implement both client-side and server-side validation
- Sanitize data before storing in database

### 2. Authentication
- Use strong password requirements
- Implement multi-factor authentication
- Use secure session management
- Implement proper logout functionality

### 3. Authorization
- Implement role-based access control (RBAC)
- Use principle of least privilege
- Validate permissions on every request
- Implement proper resource-level authorization

### 4. Data Protection
- Encrypt sensitive data at rest
- Use HTTPS for all communications
- Implement proper key management
- Regularly rotate encryption keys

### 5. Monitoring
- Enable comprehensive audit logging
- Monitor for suspicious activities
- Set up security alerts
- Regularly review security logs

### 6. Error Handling
- Don't expose sensitive information in error messages
- Log security-related errors
- Implement proper error boundaries
- Use generic error messages for users

## Database Schema

The security package requires the following database tables:

```sql
-- Audit Log table
CREATE TABLE audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID,
  session_id VARCHAR(255),
  action VARCHAR(255) NOT NULL,
  resource VARCHAR(255) NOT NULL,
  ip INET NOT NULL,
  user_agent TEXT,
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  metadata JSONB DEFAULT '{}',
  severity VARCHAR(20) DEFAULT 'medium',
  category VARCHAR(50) DEFAULT 'system',
  success BOOLEAN DEFAULT true,
  error_message TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_severity ON audit_logs(severity);
CREATE INDEX idx_audit_logs_category ON audit_logs(category);
CREATE INDEX idx_audit_logs_ip ON audit_logs(ip);

-- Security Events table (optional, for advanced monitoring)
CREATE TABLE security_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type VARCHAR(50) NOT NULL,
  severity VARCHAR(20) NOT NULL,
  source_ip INET NOT NULL,
  user_agent TEXT,
  user_id UUID,
  session_id VARCHAR(255),
  details JSONB DEFAULT '{}',
  resolved BOOLEAN DEFAULT false,
  resolved_at TIMESTAMP WITH TIME ZONE,
  resolved_by UUID,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_security_events_type ON security_events(event_type);
CREATE INDEX idx_security_events_severity ON security_events(severity);
CREATE INDEX idx_security_events_created_at ON security_events(created_at);
CREATE INDEX idx_security_events_resolved ON security_events(resolved);
```

## Testing

```bash
# Run tests
npm test

# Run tests with coverage
npm run test:cov

# Run security tests
npm run test:security
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## Security Reporting

If you discover a security vulnerability, please send an email to security@darealestgeek.com. All security vulnerabilities will be promptly addressed.

## License

This package is proprietary software for the daRealestGeek platform.

## Changelog

### v1.0.0
- Initial release
- Prompt injection protection
- SQL injection protection
- Input validation service
- Security middleware and interceptors
- Audit logging service
- Comprehensive security utilities

---

**Note**: This security package is designed to work seamlessly with the daRealestGeek platform architecture. For platform-specific implementation details, refer to the main project documentation.