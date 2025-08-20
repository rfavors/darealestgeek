/**
 * Security Module
 * Provides comprehensive security features for the daRealestGeek platform
 */

import { Module, Global, MiddlewareConsumer, NestModule } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { SecurityMiddleware } from './security.middleware';
import { PromptInjectionGuard } from './prompt-injection-guard';
import { SqlInjectionGuard } from './sql-injection-guard';
import { InputValidationService } from './input-validation.service';
import { SecurityService } from './security.service';
import { SecurityInterceptor } from './security.interceptor';
import { AuditLogService } from './audit-log.service';

@Global()
@Module({
  imports: [
    ConfigModule,
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        throttlers: [
          {
            name: 'short',
            ttl: parseInt(configService.get('THROTTLE_SHORT_TTL', '60000')), // 1 minute
            limit: parseInt(configService.get('THROTTLE_SHORT_LIMIT', '10')),
          },
          {
            name: 'medium',
            ttl: parseInt(configService.get('THROTTLE_MEDIUM_TTL', '600000')), // 10 minutes
            limit: parseInt(configService.get('THROTTLE_MEDIUM_LIMIT', '100')),
          },
          {
            name: 'long',
            ttl: parseInt(configService.get('THROTTLE_LONG_TTL', '3600000')), // 1 hour
            limit: parseInt(configService.get('THROTTLE_LONG_LIMIT', '1000')),
          },
        ],
        errorMessage: 'Too many requests, please try again later',
        skipIf: (context) => {
          const request = context.switchToHttp().getRequest();
          const configService = context.switchToHttp().getRequest().app.get(ConfigService);
          
          // Skip throttling in development if configured
          if (configService.get('NODE_ENV') === 'development' && 
              configService.get('SKIP_THROTTLING') === 'true') {
            return true;
          }
          
          // Skip for health checks
          return request.path === '/health' || request.path === '/metrics';
        },
      }),
    }),
  ],
  providers: [
    InputValidationService,
    SecurityService,
    AuditLogService,
    PromptInjectionGuard,
    SqlInjectionGuard,
    SecurityMiddleware,
    SecurityInterceptor,
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: SecurityInterceptor,
    },
  ],
  exports: [
    InputValidationService,
    SecurityService,
    AuditLogService,
    PromptInjectionGuard,
    SqlInjectionGuard,
    SecurityMiddleware,
    SecurityInterceptor,
  ],
})
export class SecurityModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(SecurityMiddleware)
      .forRoutes('*'); // Apply to all routes
  }
}

/**
 * Security configuration for different environments
 */
export const SecurityConfig = {
  development: {
    SECURITY_ENABLE_RATE_LIMIT: 'false',
    SECURITY_ENABLE_SLOW_DOWN: 'false',
    SECURITY_ENABLE_HEADERS: 'true',
    SECURITY_ENABLE_REQUEST_LOGGING: 'true',
    SECURITY_ENABLE_IP_WHITELIST: 'false',
    SECURITY_ENABLE_USER_AGENT_VALIDATION: 'false',
    SECURITY_MAX_REQUEST_SIZE: '52428800', // 50MB for development
    SECURITY_SUSPICIOUS_THRESHOLD: '50',
    THROTTLE_SHORT_LIMIT: '100',
    THROTTLE_MEDIUM_LIMIT: '1000',
    THROTTLE_LONG_LIMIT: '10000',
    SKIP_SQL_INJECTION_GUARD: 'false',
    SKIP_PROMPT_INJECTION_GUARD: 'false',
    SKIP_THROTTLING: 'false',
  },
  
  staging: {
    SECURITY_ENABLE_RATE_LIMIT: 'true',
    SECURITY_ENABLE_SLOW_DOWN: 'true',
    SECURITY_ENABLE_HEADERS: 'true',
    SECURITY_ENABLE_REQUEST_LOGGING: 'true',
    SECURITY_ENABLE_IP_WHITELIST: 'false',
    SECURITY_ENABLE_USER_AGENT_VALIDATION: 'true',
    SECURITY_MAX_REQUEST_SIZE: '10485760', // 10MB
    SECURITY_SUSPICIOUS_THRESHOLD: '20',
    THROTTLE_SHORT_LIMIT: '20',
    THROTTLE_MEDIUM_LIMIT: '200',
    THROTTLE_LONG_LIMIT: '2000',
    SKIP_SQL_INJECTION_GUARD: 'false',
    SKIP_PROMPT_INJECTION_GUARD: 'false',
    SKIP_THROTTLING: 'false',
  },
  
  production: {
    SECURITY_ENABLE_RATE_LIMIT: 'true',
    SECURITY_ENABLE_SLOW_DOWN: 'true',
    SECURITY_ENABLE_HEADERS: 'true',
    SECURITY_ENABLE_REQUEST_LOGGING: 'true',
    SECURITY_ENABLE_IP_WHITELIST: 'false',
    SECURITY_ENABLE_USER_AGENT_VALIDATION: 'true',
    SECURITY_MAX_REQUEST_SIZE: '10485760', // 10MB
    SECURITY_SUSPICIOUS_THRESHOLD: '10',
    THROTTLE_SHORT_LIMIT: '10',
    THROTTLE_MEDIUM_LIMIT: '100',
    THROTTLE_LONG_LIMIT: '1000',
    SKIP_SQL_INJECTION_GUARD: 'false',
    SKIP_PROMPT_INJECTION_GUARD: 'false',
    SKIP_THROTTLING: 'false',
  },
};

/**
 * Security decorators for easy use
 */
export { PromptInjectionProtection } from './prompt-injection-guard';
export { SqlInjectionProtection } from './sql-injection-guard';

/**
 * Re-export all security services and guards
 */
export { InputValidationService, ValidationRule, ValidationSchema, CommonValidationSchemas } from './input-validation.service';
export { SecurityService } from './security.service';
export { AuditLogService } from './audit-log.service';
export { PromptInjectionGuard } from './prompt-injection-guard';
export { SqlInjectionGuard } from './sql-injection-guard';
export { SecurityMiddleware } from './security.middleware';
export { SecurityInterceptor } from './security.interceptor';