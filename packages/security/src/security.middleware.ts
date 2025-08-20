/**
 * Security Middleware
 * Provides comprehensive security features including rate limiting, request logging, and security headers
 */

import { Injectable, NestMiddleware, Logger, HttpException, HttpStatus } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { ConfigService } from '@nestjs/config';
import rateLimit from 'express-rate-limit';
import slowDown from 'express-slow-down';
import helmet from 'helmet';
import { createHash } from 'crypto';
import { InputValidationService } from './input-validation.service';

interface SecurityConfig {
  enableRateLimit: boolean;
  enableSlowDown: boolean;
  enableSecurityHeaders: boolean;
  enableRequestLogging: boolean;
  enableIpWhitelist: boolean;
  enableUserAgentValidation: boolean;
  maxRequestSize: number;
  suspiciousActivityThreshold: number;
}

interface RateLimitConfig {
  windowMs: number;
  max: number;
  message: string;
  standardHeaders: boolean;
  legacyHeaders: boolean;
}

interface SlowDownConfig {
  windowMs: number;
  delayAfter: number;
  delayMs: number;
  maxDelayMs: number;
}

@Injectable()
export class SecurityMiddleware implements NestMiddleware {
  private readonly logger = new Logger(SecurityMiddleware.name);
  private readonly suspiciousIps = new Map<string, { count: number; lastSeen: Date }>();
  private readonly blockedIps = new Set<string>();
  private readonly whitelistedIps = new Set<string>();
  
  // Suspicious patterns in User-Agent strings
  private readonly suspiciousUserAgents = [
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
    /^$/,  // Empty user agent
    /null/i,
    /undefined/i
  ];
  
  // Legitimate bot user agents that should be allowed
  private readonly legitimateBots = [
    /googlebot/i,
    /bingbot/i,
    /slurp/i,  // Yahoo
    /duckduckbot/i,
    /baiduspider/i,
    /yandexbot/i,
    /facebookexternalhit/i,
    /twitterbot/i,
    /linkedinbot/i,
    /whatsapp/i,
    /telegrambot/i
  ];
  
  private securityConfig: SecurityConfig;
  private rateLimitConfig: RateLimitConfig;
  private slowDownConfig: SlowDownConfig;
  
  constructor(
    private configService: ConfigService,
    private inputValidationService: InputValidationService
  ) {
    this.loadConfiguration();
    this.loadWhitelistedIps();
    
    // Clean up suspicious IPs periodically
    setInterval(() => this.cleanupSuspiciousIps(), 60000); // Every minute
  }
  
  use(req: Request, res: Response, next: NextFunction) {
    try {
      // Apply security headers
      if (this.securityConfig.enableSecurityHeaders) {
        this.applySecurityHeaders(req, res);
      }
      
      // Check IP whitelist/blacklist
      if (!this.isIpAllowed(req.ip)) {
        this.logger.warn(`Blocked request from blacklisted IP: ${req.ip}`);
        throw new HttpException('Access denied', HttpStatus.FORBIDDEN);
      }
      
      // Validate User-Agent
      if (this.securityConfig.enableUserAgentValidation && !this.isUserAgentAllowed(req)) {
        this.trackSuspiciousActivity(req.ip, 'suspicious_user_agent');
        this.logger.warn(`Suspicious User-Agent from ${req.ip}: ${req.get('User-Agent')}`);
        throw new HttpException('Invalid request', HttpStatus.BAD_REQUEST);
      }
      
      // Check request size
      if (this.isRequestTooLarge(req)) {
        this.logger.warn(`Request too large from ${req.ip}: ${req.get('content-length')} bytes`);
        throw new HttpException('Request entity too large', HttpStatus.PAYLOAD_TOO_LARGE);
      }
      
      // Log security-relevant requests
      if (this.securityConfig.enableRequestLogging) {
        this.logSecurityRequest(req);
      }
      
      // Apply rate limiting
      if (this.securityConfig.enableRateLimit) {
        this.applyRateLimit(req, res, next);
      } else {
        next();
      }
    } catch (error) {
      if (error instanceof HttpException) {
        res.status(error.getStatus()).json({
          message: error.message,
          statusCode: error.getStatus(),
          timestamp: new Date().toISOString()
        });
      } else {
        this.logger.error('Security middleware error', error);
        res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
          message: 'Internal server error',
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          timestamp: new Date().toISOString()
        });
      }
    }
  }
  
  private loadConfiguration() {
    this.securityConfig = {
      enableRateLimit: this.configService.get('SECURITY_ENABLE_RATE_LIMIT', 'true') === 'true',
      enableSlowDown: this.configService.get('SECURITY_ENABLE_SLOW_DOWN', 'true') === 'true',
      enableSecurityHeaders: this.configService.get('SECURITY_ENABLE_HEADERS', 'true') === 'true',
      enableRequestLogging: this.configService.get('SECURITY_ENABLE_REQUEST_LOGGING', 'true') === 'true',
      enableIpWhitelist: this.configService.get('SECURITY_ENABLE_IP_WHITELIST', 'false') === 'true',
      enableUserAgentValidation: this.configService.get('SECURITY_ENABLE_USER_AGENT_VALIDATION', 'true') === 'true',
      maxRequestSize: parseInt(this.configService.get('SECURITY_MAX_REQUEST_SIZE', '10485760')), // 10MB
      suspiciousActivityThreshold: parseInt(this.configService.get('SECURITY_SUSPICIOUS_THRESHOLD', '10'))
    };
    
    this.rateLimitConfig = {
      windowMs: parseInt(this.configService.get('RATE_LIMIT_WINDOW_MS', '900000')), // 15 minutes
      max: parseInt(this.configService.get('RATE_LIMIT_MAX', '100')),
      message: 'Too many requests from this IP, please try again later',
      standardHeaders: true,
      legacyHeaders: false
    };
    
    this.slowDownConfig = {
      windowMs: parseInt(this.configService.get('SLOW_DOWN_WINDOW_MS', '900000')), // 15 minutes
      delayAfter: parseInt(this.configService.get('SLOW_DOWN_DELAY_AFTER', '50')),
      delayMs: parseInt(this.configService.get('SLOW_DOWN_DELAY_MS', '500')),
      maxDelayMs: parseInt(this.configService.get('SLOW_DOWN_MAX_DELAY_MS', '20000')) // 20 seconds
    };
  }
  
  private loadWhitelistedIps() {
    const whitelistEnv = this.configService.get('SECURITY_IP_WHITELIST', '');
    if (whitelistEnv) {
      const ips = whitelistEnv.split(',').map(ip => ip.trim());
      ips.forEach(ip => this.whitelistedIps.add(ip));
      this.logger.log(`Loaded ${ips.length} whitelisted IPs`);
    }
  }
  
  private applySecurityHeaders(req: Request, res: Response) {
    // Use helmet for basic security headers
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
          fontSrc: ["'self'", 'https://fonts.gstatic.com'],
          imgSrc: ["'self'", 'data:', 'https:'],
          scriptSrc: ["'self'"],
          connectSrc: ["'self'", 'https://api.openai.com', 'https://api.stripe.com'],
          frameSrc: ["'none'"],
          objectSrc: ["'none'"],
          baseUri: ["'self'"],
          formAction: ["'self'"],
          upgradeInsecureRequests: []
        }
      },
      crossOriginEmbedderPolicy: false, // Disable for API compatibility
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
      }
    })(req, res, () => {});
    
    // Additional custom headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
    res.setHeader('X-Download-Options', 'noopen');
    
    // Remove server information
    res.removeHeader('X-Powered-By');
    res.removeHeader('Server');
  }
  
  private isIpAllowed(ip: string): boolean {
    // Check if IP is blocked
    if (this.blockedIps.has(ip)) {
      return false;
    }
    
    // If whitelist is enabled, only allow whitelisted IPs
    if (this.securityConfig.enableIpWhitelist) {
      return this.whitelistedIps.has(ip) || this.isLocalIp(ip);
    }
    
    return true;
  }
  
  private isLocalIp(ip: string): boolean {
    // Allow localhost and private network IPs in development
    const localPatterns = [
      /^127\./,
      /^192\.168\./,
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^::1$/,
      /^::ffff:127\./
    ];
    
    return localPatterns.some(pattern => pattern.test(ip));
  }
  
  private isUserAgentAllowed(req: Request): boolean {
    const userAgent = req.get('User-Agent') || '';
    
    // Allow legitimate bots
    if (this.legitimateBots.some(pattern => pattern.test(userAgent))) {
      return true;
    }
    
    // Block suspicious user agents
    if (this.suspiciousUserAgents.some(pattern => pattern.test(userAgent))) {
      return false;
    }
    
    // Check for minimum user agent length and common browser patterns
    if (userAgent.length < 10) {
      return false;
    }
    
    // Allow common browsers
    const browserPatterns = [
      /mozilla/i,
      /chrome/i,
      /safari/i,
      /firefox/i,
      /edge/i,
      /opera/i
    ];
    
    return browserPatterns.some(pattern => pattern.test(userAgent));
  }
  
  private isRequestTooLarge(req: Request): boolean {
    const contentLength = parseInt(req.get('content-length') || '0');
    return contentLength > this.securityConfig.maxRequestSize;
  }
  
  private logSecurityRequest(req: Request) {
    const securityInfo = {
      ip: req.ip,
      method: req.method,
      path: req.path,
      userAgent: req.get('User-Agent'),
      referer: req.get('Referer'),
      contentType: req.get('Content-Type'),
      contentLength: req.get('Content-Length'),
      timestamp: new Date().toISOString(),
      requestId: this.generateRequestId(req)
    };
    
    // Log suspicious patterns
    if (this.hasSuspiciousPatterns(req)) {
      this.logger.warn('Suspicious request detected', securityInfo);
      this.trackSuspiciousActivity(req.ip, 'suspicious_request');
    } else {
      this.logger.debug('Security request logged', securityInfo);
    }
  }
  
  private hasSuspiciousPatterns(req: Request): boolean {
    const path = req.path.toLowerCase();
    const query = req.url.toLowerCase();
    
    // Suspicious path patterns
    const suspiciousPatterns = [
      /\.\.\//, // Directory traversal
      /\/etc\/passwd/, // System file access
      /\/proc\//, // Process information
      /\/admin/, // Admin access attempts
      /\/wp-admin/, // WordPress admin
      /\/phpmyadmin/, // Database admin
      /\.php$/, // PHP file access
      /\.asp$/, // ASP file access
      /\.jsp$/, // JSP file access
      /\/cgi-bin/, // CGI access
      /\.(git|svn|hg)/, // Version control
      /\.(env|config|ini|conf)$/, // Configuration files
      /\.(log|bak|backup|old)$/, // Backup files
      /\.(sql|db|sqlite)$/, // Database files
      /<script/i, // XSS attempts
      /javascript:/i, // JavaScript injection
      /vbscript:/i, // VBScript injection
      /onload=/i, // Event handler injection
      /onerror=/i, // Error handler injection
      /eval\(/i, // Code evaluation
      /exec\(/i, // Code execution
      /system\(/i, // System command execution
      /union.*select/i, // SQL injection
      /drop.*table/i, // SQL injection
      /insert.*into/i, // SQL injection
      /update.*set/i, // SQL injection
      /delete.*from/i // SQL injection
    ];
    
    return suspiciousPatterns.some(pattern => pattern.test(path) || pattern.test(query));
  }
  
  private trackSuspiciousActivity(ip: string, type: string) {
    const current = this.suspiciousIps.get(ip) || { count: 0, lastSeen: new Date() };
    current.count++;
    current.lastSeen = new Date();
    this.suspiciousIps.set(ip, current);
    
    // Block IP if it exceeds threshold
    if (current.count >= this.securityConfig.suspiciousActivityThreshold) {
      this.blockedIps.add(ip);
      this.logger.error(`IP ${ip} blocked due to suspicious activity (${type})`, {
        count: current.count,
        type
      });
      
      // Auto-unblock after 1 hour
      setTimeout(() => {
        this.blockedIps.delete(ip);
        this.suspiciousIps.delete(ip);
        this.logger.log(`IP ${ip} automatically unblocked`);
      }, 3600000); // 1 hour
    }
  }
  
  private cleanupSuspiciousIps() {
    const oneHourAgo = new Date(Date.now() - 3600000);
    
    for (const [ip, data] of this.suspiciousIps.entries()) {
      if (data.lastSeen < oneHourAgo) {
        this.suspiciousIps.delete(ip);
      }
    }
  }
  
  private generateRequestId(req: Request): string {
    const data = `${req.ip}-${req.method}-${req.path}-${Date.now()}`;
    return createHash('md5').update(data).digest('hex').substring(0, 8);
  }
  
  private applyRateLimit(req: Request, res: Response, next: NextFunction) {
    // Create rate limiter
    const limiter = rateLimit({
      ...this.rateLimitConfig,
      keyGenerator: (req) => {
        // Use IP + User-Agent for more granular limiting
        return `${req.ip}-${createHash('md5').update(req.get('User-Agent') || '').digest('hex').substring(0, 8)}`;
      },
      handler: (req, res) => {
        this.trackSuspiciousActivity(req.ip, 'rate_limit_exceeded');
        this.logger.warn(`Rate limit exceeded for ${req.ip}`);
        
        res.status(HttpStatus.TOO_MANY_REQUESTS).json({
          message: this.rateLimitConfig.message,
          statusCode: HttpStatus.TOO_MANY_REQUESTS,
          timestamp: new Date().toISOString(),
          retryAfter: Math.ceil(this.rateLimitConfig.windowMs / 1000)
        });
      },
      skip: (req) => {
        // Skip rate limiting for whitelisted IPs
        return this.whitelistedIps.has(req.ip) || this.isLocalIp(req.ip);
      }
    });
    
    // Apply slow down if enabled
    if (this.securityConfig.enableSlowDown) {
      const speedLimiter = slowDown({
        ...this.slowDownConfig,
        keyGenerator: (req) => req.ip,
        skip: (req) => {
          return this.whitelistedIps.has(req.ip) || this.isLocalIp(req.ip);
        }
      });
      
      speedLimiter(req, res, () => {
        limiter(req, res, next);
      });
    } else {
      limiter(req, res, next);
    }
  }
  
  /**
   * Manually block an IP address
   */
  blockIp(ip: string, reason?: string) {
    this.blockedIps.add(ip);
    this.logger.warn(`IP ${ip} manually blocked`, { reason });
  }
  
  /**
   * Manually unblock an IP address
   */
  unblockIp(ip: string) {
    this.blockedIps.delete(ip);
    this.suspiciousIps.delete(ip);
    this.logger.log(`IP ${ip} manually unblocked`);
  }
  
  /**
   * Add IP to whitelist
   */
  whitelistIp(ip: string) {
    this.whitelistedIps.add(ip);
    this.logger.log(`IP ${ip} added to whitelist`);
  }
  
  /**
   * Remove IP from whitelist
   */
  removeFromWhitelist(ip: string) {
    this.whitelistedIps.delete(ip);
    this.logger.log(`IP ${ip} removed from whitelist`);
  }
  
  /**
   * Get security statistics
   */
  getSecurityStats() {
    return {
      blockedIps: Array.from(this.blockedIps),
      whitelistedIps: Array.from(this.whitelistedIps),
      suspiciousIps: Object.fromEntries(this.suspiciousIps),
      config: this.securityConfig
    };
  }
}

/**
 * Security middleware factory
 */
export function createSecurityMiddleware(configService: ConfigService, inputValidationService: InputValidationService) {
  return new SecurityMiddleware(configService, inputValidationService);
}