/**
 * Security Interceptor
 * Provides request/response security monitoring and logging
 */

import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Observable, throwError } from 'rxjs';
import { tap, catchError } from 'rxjs/operators';
import { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { SecurityService, SecurityContext } from './security.service';
import { AuditLogService } from './audit-log.service';

interface SecurityMetrics {
  requestCount: number;
  errorCount: number;
  suspiciousRequestCount: number;
  blockedRequestCount: number;
  averageResponseTime: number;
  lastReset: Date;
}

@Injectable()
export class SecurityInterceptor implements NestInterceptor {
  private readonly logger = new Logger(SecurityInterceptor.name);
  private readonly metrics: SecurityMetrics = {
    requestCount: 0,
    errorCount: 0,
    suspiciousRequestCount: 0,
    blockedRequestCount: 0,
    averageResponseTime: 0,
    lastReset: new Date(),
  };
  
  // Sensitive data patterns to redact from logs
  private readonly sensitivePatterns = [
    /password/i,
    /token/i,
    /secret/i,
    /key/i,
    /authorization/i,
    /cookie/i,
    /session/i,
    /credit[_-]?card/i,
    /ssn/i,
    /social[_-]?security/i,
    /passport/i,
    /license/i,
  ];
  
  // Paths that should not be logged in detail
  private readonly excludedPaths = [
    '/health',
    '/metrics',
    '/favicon.ico',
    '/robots.txt',
    '/sitemap.xml',
  ];
  
  // High-risk endpoints that require extra monitoring
  private readonly highRiskEndpoints = [
    '/auth/login',
    '/auth/register',
    '/auth/reset-password',
    '/auth/change-password',
    '/admin',
    '/api/admin',
    '/users/delete',
    '/payments',
    '/api/payments',
  ];
  
  constructor(
    private configService: ConfigService,
    private securityService: SecurityService,
    private auditLogService: AuditLogService
  ) {
    // Reset metrics every hour
    setInterval(() => this.resetMetrics(), 3600000);
  }
  
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const startTime = Date.now();
    const request = context.switchToHttp().getRequest<Request>();
    const response = context.switchToHttp().getResponse<Response>();
    
    // Skip processing for excluded paths
    if (this.shouldSkipPath(request.path)) {
      return next.handle();
    }
    
    // Update metrics
    this.metrics.requestCount++;
    
    // Create security context
    const securityContext: SecurityContext = {
      ip: this.getClientIp(request),
      userAgent: request.get('User-Agent') || 'unknown',
      timestamp: new Date(),
      action: `${request.method} ${request.path}`,
      resource: request.path,
      metadata: {
        method: request.method,
        path: request.path,
        query: this.sanitizeObject(request.query),
        headers: this.sanitizeHeaders(request.headers),
        contentType: request.get('Content-Type'),
        contentLength: request.get('Content-Length'),
        referer: request.get('Referer'),
        origin: request.get('Origin'),
      },
    };
    
    // Extract user information if available
    if (request.user) {
      securityContext.userId = request.user.id || request.user.sub;
      securityContext.metadata.user = {
        id: request.user.id || request.user.sub,
        email: request.user.email,
        role: request.user.role,
      };
    }
    
    // Extract session information if available
    if (request.session) {
      securityContext.sessionId = request.session.id || request.sessionID;
    }
    
    // Check for suspicious activity
    const isSuspicious = this.detectSuspiciousActivity(request, securityContext);
    if (isSuspicious) {
      this.metrics.suspiciousRequestCount++;
      this.logger.warn('Suspicious activity detected', securityContext);
    }
    
    // Log high-risk endpoint access
    if (this.isHighRiskEndpoint(request.path)) {
      this.securityService.logSecurityEvent({
        ...securityContext,
        action: `HIGH_RISK_ACCESS: ${securityContext.action}`,
      }, 'warn');
    }
    
    return next.handle().pipe(
      tap((data) => {
        const responseTime = Date.now() - startTime;
        this.updateResponseTimeMetrics(responseTime);
        
        // Log successful requests
        this.logRequest(request, response, securityContext, responseTime, data);
      }),
      catchError((error) => {
        const responseTime = Date.now() - startTime;
        this.metrics.errorCount++;
        
        // Log error requests
        this.logError(request, response, securityContext, responseTime, error);
        
        // Enhanced logging for security-related errors
        if (this.isSecurityError(error)) {
          this.securityService.logSecurityEvent({
            ...securityContext,
            action: `SECURITY_ERROR: ${securityContext.action}`,
            metadata: {
              ...securityContext.metadata,
              error: {
                message: error.message,
                status: error.status || error.statusCode,
                stack: this.configService.get('NODE_ENV') === 'development' ? error.stack : undefined,
              },
            },
          }, 'error');
        }
        
        return throwError(() => error);
      })
    );
  }
  
  private shouldSkipPath(path: string): boolean {
    return this.excludedPaths.some(excludedPath => path.startsWith(excludedPath));
  }
  
  private isHighRiskEndpoint(path: string): boolean {
    return this.highRiskEndpoints.some(endpoint => path.startsWith(endpoint));
  }
  
  private getClientIp(request: Request): string {
    return (
      request.ip ||
      request.connection?.remoteAddress ||
      request.socket?.remoteAddress ||
      'unknown'
    );
  }
  
  private detectSuspiciousActivity(request: Request, context: SecurityContext): boolean {
    const suspiciousIndicators = [];
    
    // Check for suspicious user agent
    const userAgent = request.get('User-Agent') || '';
    if (this.isSuspiciousUserAgent(userAgent)) {
      suspiciousIndicators.push('suspicious_user_agent');
    }
    
    // Check for suspicious headers
    if (this.hasSuspiciousHeaders(request.headers)) {
      suspiciousIndicators.push('suspicious_headers');
    }
    
    // Check for suspicious query parameters
    if (this.hasSuspiciousQueryParams(request.query)) {
      suspiciousIndicators.push('suspicious_query_params');
    }
    
    // Check for suspicious path patterns
    if (this.hasSuspiciousPath(request.path)) {
      suspiciousIndicators.push('suspicious_path');
    }
    
    // Check for missing expected headers
    if (this.hasMissingExpectedHeaders(request)) {
      suspiciousIndicators.push('missing_expected_headers');
    }
    
    // Check for unusual request patterns
    if (this.hasUnusualRequestPattern(request)) {
      suspiciousIndicators.push('unusual_request_pattern');
    }
    
    if (suspiciousIndicators.length > 0) {
      context.metadata.suspiciousIndicators = suspiciousIndicators;
      return true;
    }
    
    return false;
  }
  
  private isSuspiciousUserAgent(userAgent: string): boolean {
    const suspiciousPatterns = [
      /^$/,  // Empty user agent
      /bot/i,
      /crawler/i,
      /spider/i,
      /scraper/i,
      /curl/i,
      /wget/i,
      /python/i,
      /java/i,
      /go-http-client/i,
      /okhttp/i,
      /apache-httpclient/i,
      /node-fetch/i,
      /axios/i,
      /postman/i,
      /insomnia/i,
      /httpie/i,
      /null/i,
      /undefined/i,
    ];
    
    // Allow legitimate bots
    const legitimatePatterns = [
      /googlebot/i,
      /bingbot/i,
      /slurp/i,
      /duckduckbot/i,
      /baiduspider/i,
      /yandexbot/i,
      /facebookexternalhit/i,
      /twitterbot/i,
      /linkedinbot/i,
      /whatsapp/i,
      /telegrambot/i,
    ];
    
    if (legitimatePatterns.some(pattern => pattern.test(userAgent))) {
      return false;
    }
    
    return suspiciousPatterns.some(pattern => pattern.test(userAgent));
  }
  
  private hasSuspiciousHeaders(headers: any): boolean {
    // Check for injection attempts in headers
    const headerValues = Object.values(headers).join(' ').toLowerCase();
    
    const suspiciousPatterns = [
      /<script/i,
      /javascript:/i,
      /vbscript:/i,
      /onload=/i,
      /onerror=/i,
      /eval\(/i,
      /exec\(/i,
      /union.*select/i,
      /drop.*table/i,
      /insert.*into/i,
      /update.*set/i,
      /delete.*from/i,
    ];
    
    return suspiciousPatterns.some(pattern => pattern.test(headerValues));
  }
  
  private hasSuspiciousQueryParams(query: any): boolean {
    if (!query || typeof query !== 'object') {
      return false;
    }
    
    const queryString = JSON.stringify(query).toLowerCase();
    
    const suspiciousPatterns = [
      /<script/i,
      /javascript:/i,
      /vbscript:/i,
      /onload=/i,
      /onerror=/i,
      /eval\(/i,
      /exec\(/i,
      /union.*select/i,
      /drop.*table/i,
      /insert.*into/i,
      /update.*set/i,
      /delete.*from/i,
      /\.\.\//, // Directory traversal
      /\/etc\/passwd/,
      /\/proc\//,
    ];
    
    return suspiciousPatterns.some(pattern => pattern.test(queryString));
  }
  
  private hasSuspiciousPath(path: string): boolean {
    const suspiciousPatterns = [
      /\.\.\//, // Directory traversal
      /\/etc\/passwd/,
      /\/proc\//,
      /\/admin/,
      /\/wp-admin/,
      /\/phpmyadmin/,
      /\.php$/,
      /\.asp$/,
      /\.jsp$/,
      /\/cgi-bin/,
      /\.(git|svn|hg)/,
      /\.(env|config|ini|conf)$/,
      /\.(log|bak|backup|old)$/,
      /\.(sql|db|sqlite)$/,
    ];
    
    return suspiciousPatterns.some(pattern => pattern.test(path.toLowerCase()));
  }
  
  private hasMissingExpectedHeaders(request: Request): boolean {
    // For POST/PUT/PATCH requests, expect Content-Type
    if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
      if (!request.get('Content-Type')) {
        return true;
      }
    }
    
    // For browser requests, expect Accept header
    const userAgent = request.get('User-Agent') || '';
    const isBrowser = /mozilla|chrome|safari|firefox|edge|opera/i.test(userAgent);
    if (isBrowser && !request.get('Accept')) {
      return true;
    }
    
    return false;
  }
  
  private hasUnusualRequestPattern(request: Request): boolean {
    // Check for unusual header combinations
    const headers = request.headers;
    
    // Unusual: Has Authorization but no User-Agent
    if (headers.authorization && !headers['user-agent']) {
      return true;
    }
    
    // Unusual: Has Cookie but no Accept header
    if (headers.cookie && !headers.accept) {
      return true;
    }
    
    // Unusual: POST/PUT without Content-Length or Transfer-Encoding
    if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
      if (!headers['content-length'] && !headers['transfer-encoding']) {
        return true;
      }
    }
    
    return false;
  }
  
  private isSecurityError(error: any): boolean {
    if (error instanceof HttpException) {
      const status = error.getStatus();
      return [
        HttpStatus.UNAUTHORIZED,
        HttpStatus.FORBIDDEN,
        HttpStatus.TOO_MANY_REQUESTS,
        HttpStatus.BAD_REQUEST,
      ].includes(status);
    }
    
    return false;
  }
  
  private sanitizeObject(obj: any): any {
    if (!obj || typeof obj !== 'object') {
      return obj;
    }
    
    const sanitized: any = {};
    
    for (const [key, value] of Object.entries(obj)) {
      if (this.isSensitiveField(key)) {
        sanitized[key] = '[REDACTED]';
      } else if (typeof value === 'string') {
        sanitized[key] = this.sanitizeString(value);
      } else if (typeof value === 'object' && value !== null) {
        sanitized[key] = this.sanitizeObject(value);
      } else {
        sanitized[key] = value;
      }
    }
    
    return sanitized;
  }
  
  private sanitizeHeaders(headers: any): any {
    const sanitized: any = {};
    const sensitiveHeaders = [
      'authorization',
      'cookie',
      'set-cookie',
      'x-api-key',
      'x-auth-token',
    ];
    
    for (const [key, value] of Object.entries(headers)) {
      const lowerKey = key.toLowerCase();
      if (sensitiveHeaders.includes(lowerKey)) {
        sanitized[key] = '[REDACTED]';
      } else {
        sanitized[key] = value;
      }
    }
    
    return sanitized;
  }
  
  private sanitizeString(str: string): string {
    if (str.length > 1000) {
      return str.substring(0, 1000) + '...[TRUNCATED]';
    }
    return str;
  }
  
  private isSensitiveField(fieldName: string): boolean {
    return this.sensitivePatterns.some(pattern => pattern.test(fieldName));
  }
  
  private logRequest(
    request: Request,
    response: Response,
    context: SecurityContext,
    responseTime: number,
    data?: any
  ) {
    const logData = {
      ...context,
      responseTime,
      statusCode: response.statusCode,
      responseSize: response.get('Content-Length'),
      success: true,
    };
    
    // Log to audit service
    this.auditLogService.log({
      userId: context.userId,
      action: context.action,
      resource: context.resource,
      ip: context.ip,
      userAgent: context.userAgent,
      metadata: {
        ...context.metadata,
        responseTime,
        statusCode: response.statusCode,
        success: true,
      },
    });
    
    // Log based on response status
    if (response.statusCode >= 400) {
      this.logger.warn('Request completed with error status', logData);
    } else if (this.isHighRiskEndpoint(request.path)) {
      this.logger.log('High-risk endpoint accessed successfully', logData);
    } else {
      this.logger.debug('Request completed successfully', logData);
    }
  }
  
  private logError(
    request: Request,
    response: Response,
    context: SecurityContext,
    responseTime: number,
    error: any
  ) {
    const logData = {
      ...context,
      responseTime,
      error: {
        message: error.message,
        status: error.status || error.statusCode,
        name: error.name,
      },
      success: false,
    };
    
    // Log to audit service
    this.auditLogService.log({
      userId: context.userId,
      action: `ERROR: ${context.action}`,
      resource: context.resource,
      ip: context.ip,
      userAgent: context.userAgent,
      metadata: {
        ...context.metadata,
        responseTime,
        error: logData.error,
        success: false,
      },
    });
    
    this.logger.error('Request failed', logData);
  }
  
  private updateResponseTimeMetrics(responseTime: number) {
    // Simple moving average calculation
    const alpha = 0.1; // Smoothing factor
    this.metrics.averageResponseTime = 
      this.metrics.averageResponseTime * (1 - alpha) + responseTime * alpha;
  }
  
  private resetMetrics() {
    this.logger.log('Resetting security metrics', { ...this.metrics });
    
    this.metrics.requestCount = 0;
    this.metrics.errorCount = 0;
    this.metrics.suspiciousRequestCount = 0;
    this.metrics.blockedRequestCount = 0;
    this.metrics.averageResponseTime = 0;
    this.metrics.lastReset = new Date();
  }
  
  /**
   * Get current security metrics
   */
  getMetrics(): SecurityMetrics {
    return { ...this.metrics };
  }
}