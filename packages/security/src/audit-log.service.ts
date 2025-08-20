/**
 * Audit Log Service
 * Provides comprehensive audit logging for security and compliance
 */

import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '@prisma/client';
import { SecurityService } from './security.service';

export interface AuditLogEntry {
  id?: string;
  userId?: string;
  sessionId?: string;
  action: string;
  resource: string;
  ip: string;
  userAgent: string;
  timestamp?: Date;
  metadata?: Record<string, any>;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  category?: 'authentication' | 'authorization' | 'data_access' | 'data_modification' | 'system' | 'security';
  success?: boolean;
  errorMessage?: string;
}

export interface AuditLogFilter {
  userId?: string;
  action?: string;
  resource?: string;
  ip?: string;
  startDate?: Date;
  endDate?: Date;
  severity?: string;
  category?: string;
  success?: boolean;
  limit?: number;
  offset?: number;
}

export interface AuditLogStats {
  totalLogs: number;
  logsByCategory: Record<string, number>;
  logsBySeverity: Record<string, number>;
  logsByUser: Record<string, number>;
  logsByAction: Record<string, number>;
  successRate: number;
  timeRange: {
    start: Date;
    end: Date;
  };
}

@Injectable()
export class AuditLogService {
  private readonly logger = new Logger(AuditLogService.name);
  private readonly retentionDays: number;
  private readonly enableDatabaseLogging: boolean;
  private readonly enableFileLogging: boolean;
  private readonly logBuffer: AuditLogEntry[] = [];
  private readonly bufferSize: number = 100;
  private flushTimer: NodeJS.Timeout | null = null;
  
  // Action categories for automatic classification
  private readonly actionCategories = {
    authentication: [
      'login', 'logout', 'register', 'password_reset', 'password_change',
      'mfa_enable', 'mfa_disable', 'token_refresh', 'session_create', 'session_destroy'
    ],
    authorization: [
      'permission_grant', 'permission_revoke', 'role_assign', 'role_remove',
      'access_denied', 'privilege_escalation', 'admin_access'
    ],
    data_access: [
      'view', 'read', 'list', 'search', 'export', 'download', 'print'
    ],
    data_modification: [
      'create', 'update', 'delete', 'import', 'upload', 'modify', 'edit'
    ],
    system: [
      'backup', 'restore', 'maintenance', 'configuration_change',
      'system_start', 'system_stop', 'health_check'
    ],
    security: [
      'security_scan', 'vulnerability_detected', 'intrusion_attempt',
      'suspicious_activity', 'rate_limit_exceeded', 'ip_blocked'
    ]
  };
  
  // Severity levels for automatic classification
  private readonly severityPatterns = {
    critical: [
      'privilege_escalation', 'admin_access', 'data_breach', 'system_compromise',
      'unauthorized_access', 'intrusion_attempt', 'malware_detected'
    ],
    high: [
      'login_failure', 'access_denied', 'suspicious_activity', 'rate_limit_exceeded',
      'password_reset', 'permission_change', 'sensitive_data_access'
    ],
    medium: [
      'login_success', 'logout', 'data_modification', 'configuration_change',
      'user_creation', 'role_assignment'
    ],
    low: [
      'data_access', 'view', 'read', 'list', 'health_check', 'routine_operation'
    ]
  };
  
  constructor(
    private configService: ConfigService,
    private prismaService: PrismaService,
    private securityService: SecurityService
  ) {
    this.retentionDays = this.configService.get<number>('AUDIT_LOG_RETENTION_DAYS', 90);
    this.enableDatabaseLogging = this.configService.get<boolean>('AUDIT_LOG_DATABASE_ENABLED', true);
    this.enableFileLogging = this.configService.get<boolean>('AUDIT_LOG_FILE_ENABLED', true);
    
    // Start periodic flush
    this.startPeriodicFlush();
    
    // Start cleanup job
    this.startCleanupJob();
  }
  
  /**
   * Log an audit entry
   */
  async log(entry: Omit<AuditLogEntry, 'id' | 'timestamp'>): Promise<void> {
    try {
      const auditEntry: AuditLogEntry = {
        ...entry,
        timestamp: new Date(),
        category: entry.category || this.categorizeAction(entry.action),
        severity: entry.severity || this.determineSeverity(entry.action, entry.success),
      };
      
      // Add to buffer for batch processing
      this.logBuffer.push(auditEntry);
      
      // Immediate flush for critical events
      if (auditEntry.severity === 'critical') {
        await this.flushBuffer();
      }
      
      // Flush buffer if it's full
      if (this.logBuffer.length >= this.bufferSize) {
        await this.flushBuffer();
      }
      
      // Log to application logger based on severity
      this.logToApplicationLogger(auditEntry);
      
    } catch (error) {
      this.logger.error('Failed to log audit entry', {
        error: error.message,
        entry: this.sanitizeEntry(entry),
      });
    }
  }
  
  /**
   * Log authentication events
   */
  async logAuthentication(
    action: string,
    userId: string | null,
    ip: string,
    userAgent: string,
    success: boolean,
    metadata?: Record<string, any>
  ): Promise<void> {
    await this.log({
      userId,
      action: `AUTH_${action.toUpperCase()}`,
      resource: 'authentication',
      ip,
      userAgent,
      success,
      category: 'authentication',
      severity: success ? 'medium' : 'high',
      metadata,
    });
  }
  
  /**
   * Log data access events
   */
  async logDataAccess(
    userId: string,
    action: string,
    resource: string,
    ip: string,
    userAgent: string,
    metadata?: Record<string, any>
  ): Promise<void> {
    await this.log({
      userId,
      action: `DATA_${action.toUpperCase()}`,
      resource,
      ip,
      userAgent,
      success: true,
      category: 'data_access',
      severity: this.isResourceSensitive(resource) ? 'high' : 'low',
      metadata,
    });
  }
  
  /**
   * Log security events
   */
  async logSecurityEvent(
    action: string,
    ip: string,
    userAgent: string,
    severity: 'low' | 'medium' | 'high' | 'critical' = 'medium',
    metadata?: Record<string, any>
  ): Promise<void> {
    await this.log({
      action: `SECURITY_${action.toUpperCase()}`,
      resource: 'security',
      ip,
      userAgent,
      success: false,
      category: 'security',
      severity,
      metadata,
    });
  }
  
  /**
   * Log admin actions
   */
  async logAdminAction(
    userId: string,
    action: string,
    resource: string,
    ip: string,
    userAgent: string,
    success: boolean,
    metadata?: Record<string, any>
  ): Promise<void> {
    await this.log({
      userId,
      action: `ADMIN_${action.toUpperCase()}`,
      resource,
      ip,
      userAgent,
      success,
      category: 'authorization',
      severity: 'high',
      metadata,
    });
  }
  
  /**
   * Search audit logs
   */
  async searchLogs(filter: AuditLogFilter): Promise<AuditLogEntry[]> {
    try {
      if (!this.enableDatabaseLogging) {
        this.logger.warn('Database logging is disabled, cannot search logs');
        return [];
      }
      
      const where: any = {};
      
      if (filter.userId) where.userId = filter.userId;
      if (filter.action) where.action = { contains: filter.action, mode: 'insensitive' };
      if (filter.resource) where.resource = { contains: filter.resource, mode: 'insensitive' };
      if (filter.ip) where.ip = filter.ip;
      if (filter.severity) where.severity = filter.severity;
      if (filter.category) where.category = filter.category;
      if (filter.success !== undefined) where.success = filter.success;
      
      if (filter.startDate || filter.endDate) {
        where.timestamp = {};
        if (filter.startDate) where.timestamp.gte = filter.startDate;
        if (filter.endDate) where.timestamp.lte = filter.endDate;
      }
      
      const logs = await this.prismaService.auditLog.findMany({
        where,
        orderBy: { timestamp: 'desc' },
        take: filter.limit || 100,
        skip: filter.offset || 0,
      });
      
      return logs.map(log => ({
        id: log.id,
        userId: log.userId,
        sessionId: log.sessionId,
        action: log.action,
        resource: log.resource,
        ip: log.ip,
        userAgent: log.userAgent,
        timestamp: log.timestamp,
        metadata: log.metadata as Record<string, any>,
        severity: log.severity as 'low' | 'medium' | 'high' | 'critical',
        category: log.category as any,
        success: log.success,
        errorMessage: log.errorMessage,
      }));
      
    } catch (error) {
      this.logger.error('Failed to search audit logs', {
        error: error.message,
        filter,
      });
      return [];
    }
  }
  
  /**
   * Get audit log statistics
   */
  async getStats(startDate?: Date, endDate?: Date): Promise<AuditLogStats> {
    try {
      if (!this.enableDatabaseLogging) {
        throw new Error('Database logging is disabled');
      }
      
      const where: any = {};
      if (startDate || endDate) {
        where.timestamp = {};
        if (startDate) where.timestamp.gte = startDate;
        if (endDate) where.timestamp.lte = endDate;
      }
      
      const [totalLogs, categoryStats, severityStats, userStats, actionStats] = await Promise.all([
        this.prismaService.auditLog.count({ where }),
        this.prismaService.auditLog.groupBy({
          by: ['category'],
          where,
          _count: { category: true },
        }),
        this.prismaService.auditLog.groupBy({
          by: ['severity'],
          where,
          _count: { severity: true },
        }),
        this.prismaService.auditLog.groupBy({
          by: ['userId'],
          where: { ...where, userId: { not: null } },
          _count: { userId: true },
          take: 10,
          orderBy: { _count: { userId: 'desc' } },
        }),
        this.prismaService.auditLog.groupBy({
          by: ['action'],
          where,
          _count: { action: true },
          take: 10,
          orderBy: { _count: { action: 'desc' } },
        }),
      ]);
      
      const successCount = await this.prismaService.auditLog.count({
        where: { ...where, success: true },
      });
      
      const timeRange = await this.prismaService.auditLog.aggregate({
        where,
        _min: { timestamp: true },
        _max: { timestamp: true },
      });
      
      return {
        totalLogs,
        logsByCategory: categoryStats.reduce((acc, stat) => {
          acc[stat.category || 'unknown'] = stat._count.category;
          return acc;
        }, {} as Record<string, number>),
        logsBySeverity: severityStats.reduce((acc, stat) => {
          acc[stat.severity || 'unknown'] = stat._count.severity;
          return acc;
        }, {} as Record<string, number>),
        logsByUser: userStats.reduce((acc, stat) => {
          acc[stat.userId || 'unknown'] = stat._count.userId;
          return acc;
        }, {} as Record<string, number>),
        logsByAction: actionStats.reduce((acc, stat) => {
          acc[stat.action] = stat._count.action;
          return acc;
        }, {} as Record<string, number>),
        successRate: totalLogs > 0 ? (successCount / totalLogs) * 100 : 0,
        timeRange: {
          start: timeRange._min.timestamp || new Date(),
          end: timeRange._max.timestamp || new Date(),
        },
      };
      
    } catch (error) {
      this.logger.error('Failed to get audit log stats', {
        error: error.message,
      });
      throw error;
    }
  }
  
  /**
   * Export audit logs
   */
  async exportLogs(
    filter: AuditLogFilter,
    format: 'json' | 'csv' = 'json'
  ): Promise<string> {
    try {
      const logs = await this.searchLogs({ ...filter, limit: 10000 });
      
      if (format === 'csv') {
        return this.convertToCSV(logs);
      }
      
      return JSON.stringify(logs, null, 2);
      
    } catch (error) {
      this.logger.error('Failed to export audit logs', {
        error: error.message,
        filter,
        format,
      });
      throw error;
    }
  }
  
  /**
   * Clean up old audit logs
   */
  async cleanup(): Promise<number> {
    try {
      if (!this.enableDatabaseLogging) {
        return 0;
      }
      
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - this.retentionDays);
      
      const result = await this.prismaService.auditLog.deleteMany({
        where: {
          timestamp: {
            lt: cutoffDate,
          },
        },
      });
      
      this.logger.log(`Cleaned up ${result.count} old audit log entries`, {
        cutoffDate,
        retentionDays: this.retentionDays,
      });
      
      return result.count;
      
    } catch (error) {
      this.logger.error('Failed to cleanup audit logs', {
        error: error.message,
      });
      throw error;
    }
  }
  
  private async flushBuffer(): Promise<void> {
    if (this.logBuffer.length === 0) {
      return;
    }
    
    const entries = [...this.logBuffer];
    this.logBuffer.length = 0;
    
    try {
      // Save to database if enabled
      if (this.enableDatabaseLogging) {
        await this.saveToDatabaseBatch(entries);
      }
      
      // Save to file if enabled
      if (this.enableFileLogging) {
        await this.saveToFileBatch(entries);
      }
      
    } catch (error) {
      this.logger.error('Failed to flush audit log buffer', {
        error: error.message,
        entriesCount: entries.length,
      });
      
      // Re-add entries to buffer for retry
      this.logBuffer.unshift(...entries);
    }
  }
  
  private async saveToDatabaseBatch(entries: AuditLogEntry[]): Promise<void> {
    try {
      await this.prismaService.auditLog.createMany({
        data: entries.map(entry => ({
          userId: entry.userId,
          sessionId: entry.sessionId,
          action: entry.action,
          resource: entry.resource,
          ip: entry.ip,
          userAgent: entry.userAgent,
          timestamp: entry.timestamp!,
          metadata: entry.metadata || {},
          severity: entry.severity!,
          category: entry.category!,
          success: entry.success,
          errorMessage: entry.errorMessage,
        })),
      });
      
    } catch (error) {
      this.logger.error('Failed to save audit logs to database', {
        error: error.message,
        entriesCount: entries.length,
      });
      throw error;
    }
  }
  
  private async saveToFileBatch(entries: AuditLogEntry[]): Promise<void> {
    // File logging implementation would go here
    // For now, just log to application logger
    entries.forEach(entry => {
      this.logger.log('AUDIT_LOG', entry);
    });
  }
  
  private categorizeAction(action: string): string {
    const lowerAction = action.toLowerCase();
    
    for (const [category, actions] of Object.entries(this.actionCategories)) {
      if (actions.some(a => lowerAction.includes(a))) {
        return category;
      }
    }
    
    return 'system';
  }
  
  private determineSeverity(action: string, success?: boolean): 'low' | 'medium' | 'high' | 'critical' {
    const lowerAction = action.toLowerCase();
    
    // Failed actions are generally more severe
    if (success === false) {
      for (const [severity, patterns] of Object.entries(this.severityPatterns)) {
        if (patterns.some(p => lowerAction.includes(p))) {
          // Bump up severity for failed actions
          if (severity === 'low') return 'medium';
          if (severity === 'medium') return 'high';
          if (severity === 'high') return 'critical';
          return severity as any;
        }
      }
      return 'medium'; // Default for failed actions
    }
    
    // Successful actions
    for (const [severity, patterns] of Object.entries(this.severityPatterns)) {
      if (patterns.some(p => lowerAction.includes(p))) {
        return severity as any;
      }
    }
    
    return 'low'; // Default severity
  }
  
  private isResourceSensitive(resource: string): boolean {
    const sensitiveResources = [
      'user', 'admin', 'payment', 'billing', 'financial',
      'personal', 'private', 'confidential', 'secret',
      'password', 'token', 'key', 'credential'
    ];
    
    const lowerResource = resource.toLowerCase();
    return sensitiveResources.some(sr => lowerResource.includes(sr));
  }
  
  private logToApplicationLogger(entry: AuditLogEntry): void {
    const logData = this.sanitizeEntry(entry);
    
    switch (entry.severity) {
      case 'critical':
        this.logger.error('CRITICAL AUDIT EVENT', logData);
        break;
      case 'high':
        this.logger.warn('HIGH SEVERITY AUDIT EVENT', logData);
        break;
      case 'medium':
        this.logger.log('AUDIT EVENT', logData);
        break;
      case 'low':
      default:
        this.logger.debug('AUDIT EVENT', logData);
        break;
    }
  }
  
  private sanitizeEntry(entry: any): any {
    const sanitized = { ...entry };
    
    // Remove sensitive data from metadata
    if (sanitized.metadata) {
      sanitized.metadata = this.securityService.maskSensitiveData(sanitized.metadata);
    }
    
    // Truncate long strings
    if (sanitized.userAgent && sanitized.userAgent.length > 500) {
      sanitized.userAgent = sanitized.userAgent.substring(0, 500) + '...';
    }
    
    return sanitized;
  }
  
  private convertToCSV(logs: AuditLogEntry[]): string {
    if (logs.length === 0) {
      return 'No data';
    }
    
    const headers = [
      'timestamp', 'userId', 'action', 'resource', 'ip',
      'userAgent', 'severity', 'category', 'success', 'errorMessage'
    ];
    
    const csvRows = [headers.join(',')];
    
    logs.forEach(log => {
      const row = headers.map(header => {
        let value = log[header as keyof AuditLogEntry];
        
        if (value === null || value === undefined) {
          return '';
        }
        
        if (typeof value === 'object') {
          value = JSON.stringify(value);
        }
        
        // Escape quotes and wrap in quotes if contains comma
        const stringValue = String(value).replace(/"/g, '""');
        return stringValue.includes(',') ? `"${stringValue}"` : stringValue;
      });
      
      csvRows.push(row.join(','));
    });
    
    return csvRows.join('\n');
  }
  
  private startPeriodicFlush(): void {
    // Flush buffer every 30 seconds
    this.flushTimer = setInterval(async () => {
      await this.flushBuffer();
    }, 30000);
  }
  
  private startCleanupJob(): void {
    // Run cleanup daily at 2 AM
    const now = new Date();
    const tomorrow2AM = new Date(now);
    tomorrow2AM.setDate(tomorrow2AM.getDate() + 1);
    tomorrow2AM.setHours(2, 0, 0, 0);
    
    const msUntil2AM = tomorrow2AM.getTime() - now.getTime();
    
    setTimeout(() => {
      this.cleanup();
      
      // Then run every 24 hours
      setInterval(() => {
        this.cleanup();
      }, 24 * 60 * 60 * 1000);
    }, msUntil2AM);
  }
  
  /**
   * Graceful shutdown
   */
  async onModuleDestroy(): Promise<void> {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
    }
    
    // Flush remaining buffer
    await this.flushBuffer();
  }
}