#!/usr/bin/env node

/**
 * Security Monitoring Script for daRealestGeek Platform
 * 
 * This script continuously monitors security events and generates alerts for:
 * - Failed authentication attempts
 * - Suspicious activity patterns
 * - Rate limit violations
 * - Injection attack attempts
 * - Unusual traffic patterns
 * - System security health
 */

const axios = require('axios');
const chalk = require('chalk');
const cron = require('node-cron');
const fs = require('fs-extra');
const path = require('path');
const { Command } = require('commander');
require('dotenv').config();

// Configuration
const config = {
  apiUrl: process.env.API_URL || 'http://localhost:3001',
  adminToken: process.env.ADMIN_TOKEN,
  alertWebhook: process.env.ALERT_WEBHOOK_URL,
  emailAlert: process.env.ALERT_EMAIL,
  monitoringInterval: process.env.MONITORING_INTERVAL || '*/5 * * * *', // Every 5 minutes
  logFile: path.join(__dirname, '../logs/security-monitor.log'),
  alertsFile: path.join(__dirname, '../logs/security-alerts.json'),
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
};

// Create axios instance
const api = axios.create({
  baseURL: config.apiUrl,
  timeout: 10000,
  headers: {
    'Authorization': `Bearer ${config.adminToken}`,
    'Content-Type': 'application/json',
  },
});

// Monitoring state
const monitoringState = {
  isRunning: false,
  lastCheck: null,
  alerts: [],
  stats: {
    totalChecks: 0,
    alertsGenerated: 0,
    lastAlert: null,
  },
};

// Utility functions
function log(message, level = 'info') {
  const timestamp = new Date().toISOString();
  const colors = {
    info: chalk.blue,
    warn: chalk.yellow,
    error: chalk.red,
    success: chalk.green,
    debug: chalk.gray,
  };
  
  const logMessage = `[${timestamp}] [${level.toUpperCase()}] ${message}`;
  console.log(colors[level](logMessage));
  
  // Write to log file
  fs.ensureDirSync(path.dirname(config.logFile));
  fs.appendFileSync(config.logFile, logMessage + '\n');
}

function logAlert(alert) {
  log(`🚨 SECURITY ALERT: ${alert.type} - ${alert.message}`, 'error');
  
  // Save alert to file
  fs.ensureDirSync(path.dirname(config.alertsFile));
  const alerts = loadAlerts();
  alerts.push({
    ...alert,
    timestamp: new Date().toISOString(),
    id: generateAlertId(),
  });
  fs.writeFileSync(config.alertsFile, JSON.stringify(alerts, null, 2));
  
  // Send external notifications
  sendAlertNotification(alert);
  
  monitoringState.alerts.push(alert);
  monitoringState.stats.alertsGenerated++;
  monitoringState.stats.lastAlert = new Date();
}

function loadAlerts() {
  try {
    if (fs.existsSync(config.alertsFile)) {
      return JSON.parse(fs.readFileSync(config.alertsFile, 'utf8'));
    }
  } catch (error) {
    log(`Error loading alerts: ${error.message}`, 'error');
  }
  return [];
}

function generateAlertId() {
  return `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

async function sendAlertNotification(alert) {
  try {
    // Send webhook notification
    if (config.alertWebhook) {
      await axios.post(config.alertWebhook, {
        text: `🚨 Security Alert: ${alert.type}`,
        attachments: [{
          color: 'danger',
          fields: [
            { title: 'Type', value: alert.type, short: true },
            { title: 'Severity', value: alert.severity, short: true },
            { title: 'Message', value: alert.message, short: false },
            { title: 'Details', value: JSON.stringify(alert.details, null, 2), short: false },
          ],
          timestamp: new Date().toISOString(),
        }],
      });
    }
    
    // Send email notification (if configured)
    if (config.emailAlert) {
      // Implementation depends on your email service
      log(`Email alert would be sent to: ${config.emailAlert}`, 'debug');
    }
  } catch (error) {
    log(`Error sending alert notification: ${error.message}`, 'error');
  }
}

// Security monitoring functions
class SecurityMonitor {
  constructor() {
    this.lastCheckTime = new Date(Date.now() - 5 * 60 * 1000); // 5 minutes ago
  }

  async startMonitoring() {
    log('🛡️  Starting Security Monitoring', 'info');
    log(`API URL: ${config.apiUrl}`);
    log(`Monitoring interval: ${config.monitoringInterval}`);
    
    monitoringState.isRunning = true;
    
    // Initial check
    await this.performSecurityCheck();
    
    // Schedule periodic checks
    cron.schedule(config.monitoringInterval, async () => {
      if (monitoringState.isRunning) {
        await this.performSecurityCheck();
      }
    });
    
    log('Security monitoring started successfully', 'success');
  }

  async stopMonitoring() {
    log('Stopping security monitoring...', 'info');
    monitoringState.isRunning = false;
    log('Security monitoring stopped', 'success');
  }

  async performSecurityCheck() {
    try {
      log('Performing security check...', 'debug');
      
      const currentTime = new Date();
      const timeWindow = {
        start: this.lastCheckTime,
        end: currentTime,
      };
      
      // Check authentication failures
      await this.checkAuthenticationFailures(timeWindow);
      
      // Check injection attempts
      await this.checkInjectionAttempts(timeWindow);
      
      // Check rate limiting violations
      await this.checkRateLimitViolations(timeWindow);
      
      // Check suspicious IP activity
      await this.checkSuspiciousIPs(timeWindow);
      
      // Check system health
      await this.checkSystemHealth();
      
      // Check for unusual patterns
      await this.checkUnusualPatterns(timeWindow);
      
      this.lastCheckTime = currentTime;
      monitoringState.lastCheck = currentTime;
      monitoringState.stats.totalChecks++;
      
      log('Security check completed', 'debug');
    } catch (error) {
      log(`Error during security check: ${error.message}`, 'error');
    }
  }

  async checkAuthenticationFailures(timeWindow) {
    try {
      const response = await api.get('/api/admin/security/audit-logs', {
        params: {
          action: 'LOGIN_INVALID_PASSWORD,LOGIN_USER_NOT_FOUND',
          startDate: timeWindow.start.toISOString(),
          endDate: timeWindow.end.toISOString(),
          success: false,
        },
      });
      
      if (response.status === 200) {
        const failures = response.data.logs || [];
        const failureCount = failures.length;
        
        // Check thresholds
        const timeSpanMinutes = (timeWindow.end - timeWindow.start) / (1000 * 60);
        const failuresPerMinute = failureCount / timeSpanMinutes;
        
        if (failuresPerMinute > config.thresholds.failedLogins.perMinute) {
          logAlert({
            type: 'HIGH_AUTHENTICATION_FAILURES',
            severity: 'high',
            message: `High rate of authentication failures detected: ${failureCount} failures in ${timeSpanMinutes.toFixed(1)} minutes`,
            details: {
              failureCount,
              timeSpanMinutes,
              failuresPerMinute: failuresPerMinute.toFixed(2),
              threshold: config.thresholds.failedLogins.perMinute,
              recentFailures: failures.slice(0, 5), // Show first 5
            },
          });
        }
        
        // Check for brute force patterns
        const ipFailures = {};
        failures.forEach(failure => {
          const ip = failure.ip;
          ipFailures[ip] = (ipFailures[ip] || 0) + 1;
        });
        
        Object.entries(ipFailures).forEach(([ip, count]) => {
          if (count >= 5) {
            logAlert({
              type: 'BRUTE_FORCE_ATTEMPT',
              severity: 'critical',
              message: `Potential brute force attack from IP ${ip}: ${count} failed attempts`,
              details: {
                sourceIP: ip,
                attemptCount: count,
                timeWindow: timeSpanMinutes,
              },
            });
          }
        });
      }
    } catch (error) {
      log(`Error checking authentication failures: ${error.message}`, 'error');
    }
  }

  async checkInjectionAttempts(timeWindow) {
    try {
      const response = await api.get('/api/admin/security/audit-logs', {
        params: {
          category: 'security',
          severity: 'high,critical',
          startDate: timeWindow.start.toISOString(),
          endDate: timeWindow.end.toISOString(),
        },
      });
      
      if (response.status === 200) {
        const securityEvents = response.data.logs || [];
        const injectionAttempts = securityEvents.filter(event => 
          event.action && (
            event.action.includes('INJECTION') ||
            event.action.includes('XSS') ||
            event.action.includes('MALICIOUS')
          )
        );
        
        if (injectionAttempts.length > 0) {
          const timeSpanMinutes = (timeWindow.end - timeWindow.start) / (1000 * 60);
          const attemptsPerMinute = injectionAttempts.length / timeSpanMinutes;
          
          if (attemptsPerMinute > config.thresholds.injectionAttempts.perMinute) {
            logAlert({
              type: 'HIGH_INJECTION_ATTEMPTS',
              severity: 'critical',
              message: `High rate of injection attempts detected: ${injectionAttempts.length} attempts in ${timeSpanMinutes.toFixed(1)} minutes`,
              details: {
                attemptCount: injectionAttempts.length,
                timeSpanMinutes,
                attemptsPerMinute: attemptsPerMinute.toFixed(2),
                threshold: config.thresholds.injectionAttempts.perMinute,
                recentAttempts: injectionAttempts.slice(0, 3),
              },
            });
          }
        }
      }
    } catch (error) {
      log(`Error checking injection attempts: ${error.message}`, 'error');
    }
  }

  async checkRateLimitViolations(timeWindow) {
    try {
      const response = await api.get('/api/admin/security/audit-logs', {
        params: {
          action: 'RATE_LIMIT_EXCEEDED',
          startDate: timeWindow.start.toISOString(),
          endDate: timeWindow.end.toISOString(),
        },
      });
      
      if (response.status === 200) {
        const violations = response.data.logs || [];
        
        if (violations.length > 0) {
          const timeSpanMinutes = (timeWindow.end - timeWindow.start) / (1000 * 60);
          const violationsPerMinute = violations.length / timeSpanMinutes;
          
          if (violationsPerMinute > config.thresholds.rateLimitHits.perMinute) {
            logAlert({
              type: 'HIGH_RATE_LIMIT_VIOLATIONS',
              severity: 'medium',
              message: `High rate of rate limit violations: ${violations.length} violations in ${timeSpanMinutes.toFixed(1)} minutes`,
              details: {
                violationCount: violations.length,
                timeSpanMinutes,
                violationsPerMinute: violationsPerMinute.toFixed(2),
                threshold: config.thresholds.rateLimitHits.perMinute,
              },
            });
          }
        }
      }
    } catch (error) {
      log(`Error checking rate limit violations: ${error.message}`, 'error');
    }
  }

  async checkSuspiciousIPs(timeWindow) {
    try {
      const response = await api.get('/api/admin/security/audit-logs', {
        params: {
          success: false,
          startDate: timeWindow.start.toISOString(),
          endDate: timeWindow.end.toISOString(),
        },
      });
      
      if (response.status === 200) {
        const failedEvents = response.data.logs || [];
        const ipActivity = {};
        
        failedEvents.forEach(event => {
          const ip = event.ip;
          if (!ipActivity[ip]) {
            ipActivity[ip] = {
              count: 0,
              actions: new Set(),
              firstSeen: event.timestamp,
              lastSeen: event.timestamp,
            };
          }
          
          ipActivity[ip].count++;
          ipActivity[ip].actions.add(event.action);
          ipActivity[ip].lastSeen = event.timestamp;
        });
        
        Object.entries(ipActivity).forEach(([ip, activity]) => {
          if (activity.count >= config.thresholds.suspiciousIPs.uniqueFailures &&
              activity.actions.size >= 2) {
            logAlert({
              type: 'SUSPICIOUS_IP_ACTIVITY',
              severity: 'high',
              message: `Suspicious activity from IP ${ip}: ${activity.count} failed attempts across ${activity.actions.size} different actions`,
              details: {
                sourceIP: ip,
                failureCount: activity.count,
                uniqueActions: Array.from(activity.actions),
                firstSeen: activity.firstSeen,
                lastSeen: activity.lastSeen,
              },
            });
          }
        });
      }
    } catch (error) {
      log(`Error checking suspicious IPs: ${error.message}`, 'error');
    }
  }

  async checkSystemHealth() {
    try {
      // Check API health
      const healthResponse = await api.get('/health');
      if (healthResponse.status !== 200) {
        logAlert({
          type: 'SYSTEM_HEALTH_DEGRADED',
          severity: 'high',
          message: `API health check failed with status ${healthResponse.status}`,
          details: {
            status: healthResponse.status,
            response: healthResponse.data,
          },
        });
      }
      
      // Check security service health
      const securityHealthResponse = await api.get('/api/admin/security/health');
      if (securityHealthResponse.status === 200) {
        const healthData = securityHealthResponse.data;
        
        // Check for any critical issues
        if (healthData.issues && healthData.issues.length > 0) {
          const criticalIssues = healthData.issues.filter(issue => issue.severity === 'critical');
          if (criticalIssues.length > 0) {
            logAlert({
              type: 'SECURITY_SYSTEM_ISSUES',
              severity: 'critical',
              message: `Critical security system issues detected: ${criticalIssues.length} issues`,
              details: {
                criticalIssues,
                allIssues: healthData.issues,
              },
            });
          }
        }
      }
    } catch (error) {
      if (error.response?.status !== 404) {
        log(`Error checking system health: ${error.message}`, 'error');
      }
    }
  }

  async checkUnusualPatterns(timeWindow) {
    try {
      const response = await api.get('/api/admin/security/audit-stats', {
        params: {
          startDate: timeWindow.start.toISOString(),
          endDate: timeWindow.end.toISOString(),
        },
      });
      
      if (response.status === 200) {
        const stats = response.data;
        
        // Check for unusual traffic patterns
        if (stats.totalLogs > 0) {
          const successRate = (stats.successfulLogs / stats.totalLogs) * 100;
          
          if (successRate < 50 && stats.totalLogs > 20) {
            logAlert({
              type: 'LOW_SUCCESS_RATE',
              severity: 'medium',
              message: `Unusually low success rate detected: ${successRate.toFixed(1)}% (${stats.successfulLogs}/${stats.totalLogs})`,
              details: {
                successRate: successRate.toFixed(1),
                totalLogs: stats.totalLogs,
                successfulLogs: stats.successfulLogs,
                failedLogs: stats.totalLogs - stats.successfulLogs,
              },
            });
          }
        }
        
        // Check for unusual category distributions
        if (stats.logsByCategory) {
          const securityLogs = stats.logsByCategory.security || 0;
          const totalLogs = stats.totalLogs;
          
          if (securityLogs > 0 && (securityLogs / totalLogs) > 0.1) {
            logAlert({
              type: 'HIGH_SECURITY_EVENT_RATIO',
              severity: 'medium',
              message: `High ratio of security events: ${securityLogs}/${totalLogs} (${((securityLogs / totalLogs) * 100).toFixed(1)}%)`,
              details: {
                securityLogs,
                totalLogs,
                ratio: ((securityLogs / totalLogs) * 100).toFixed(1),
                categoryBreakdown: stats.logsByCategory,
              },
            });
          }
        }
      }
    } catch (error) {
      if (error.response?.status !== 404) {
        log(`Error checking unusual patterns: ${error.message}`, 'error');
      }
    }
  }

  getMonitoringStatus() {
    return {
      isRunning: monitoringState.isRunning,
      lastCheck: monitoringState.lastCheck,
      stats: monitoringState.stats,
      recentAlerts: monitoringState.alerts.slice(-5),
    };
  }
}

// CLI interface
const program = new Command();

program
  .name('security-monitor')
  .description('Security monitoring for daRealestGeek platform')
  .version('1.0.0');

program
  .command('start')
  .description('Start security monitoring')
  .option('-d, --daemon', 'Run as daemon')
  .action(async (options) => {
    const monitor = new SecurityMonitor();
    
    if (options.daemon) {
      log('Starting security monitoring in daemon mode...', 'info');
      process.on('SIGINT', async () => {
        await monitor.stopMonitoring();
        process.exit(0);
      });
      
      process.on('SIGTERM', async () => {
        await monitor.stopMonitoring();
        process.exit(0);
      });
    }
    
    await monitor.startMonitoring();
    
    if (!options.daemon) {
      // Run for a single check and exit
      setTimeout(async () => {
        await monitor.stopMonitoring();
        process.exit(0);
      }, 10000);
    }
  });

program
  .command('status')
  .description('Show monitoring status')
  .action(() => {
    const alerts = loadAlerts();
    const recentAlerts = alerts.slice(-10);
    
    console.log(chalk.cyan.bold('\n🛡️  Security Monitoring Status'));
    console.log(`Total alerts: ${alerts.length}`);
    console.log(`Recent alerts (last 10):`);
    
    if (recentAlerts.length === 0) {
      console.log(chalk.green('  No recent alerts'));
    } else {
      recentAlerts.forEach(alert => {
        const color = alert.severity === 'critical' ? chalk.red : 
                     alert.severity === 'high' ? chalk.yellow : chalk.blue;
        console.log(`  ${color(alert.timestamp)} - ${alert.type}: ${alert.message}`);
      });
    }
  });

program
  .command('test')
  .description('Test monitoring functionality')
  .action(async () => {
    log('Testing security monitoring...', 'info');
    const monitor = new SecurityMonitor();
    await monitor.performSecurityCheck();
    log('Test completed', 'success');
  });

program
  .command('alerts')
  .description('Show recent alerts')
  .option('-n, --number <count>', 'Number of alerts to show', '20')
  .option('-s, --severity <level>', 'Filter by severity (critical, high, medium, low)')
  .action((options) => {
    const alerts = loadAlerts();
    let filteredAlerts = alerts;
    
    if (options.severity) {
      filteredAlerts = alerts.filter(alert => alert.severity === options.severity);
    }
    
    const recentAlerts = filteredAlerts.slice(-parseInt(options.number));
    
    console.log(chalk.cyan.bold(`\n🚨 Security Alerts (${recentAlerts.length})`));
    
    if (recentAlerts.length === 0) {
      console.log(chalk.green('No alerts found'));
    } else {
      recentAlerts.forEach(alert => {
        const color = alert.severity === 'critical' ? chalk.red : 
                     alert.severity === 'high' ? chalk.yellow : chalk.blue;
        console.log(`\n${color('■')} ${alert.type} (${alert.severity})`);
        console.log(`  Time: ${alert.timestamp}`);
        console.log(`  Message: ${alert.message}`);
        if (alert.details) {
          console.log(`  Details: ${JSON.stringify(alert.details, null, 2)}`);
        }
      });
    }
  });

// Execute CLI
if (require.main === module) {
  program.parse();
}

module.exports = SecurityMonitor;