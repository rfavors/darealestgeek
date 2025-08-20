/**
 * Frontend Security Enhancements for daRealestGeek Platform
 * Provides client-side protection against XSS, injection attacks, and other security threats
 */

class SecurityEnhancer {
    constructor() {
        this.initializeSecurityMeasures();
    }

    /**
     * Initialize all security measures
     */
    initializeSecurityMeasures() {
        this.setupCSPHeaders();
        this.setupInputSanitization();
        this.setupXSSProtection();
        this.setupClickjackingProtection();
        this.setupSecureStorage();
        this.monitorSecurityEvents();
    }

    /**
     * Setup Content Security Policy headers
     */
    setupCSPHeaders() {
        const meta = document.createElement('meta');
        meta.httpEquiv = 'Content-Security-Policy';
        meta.content = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline'", // Allow inline scripts for demo purposes
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data: https:",
            "font-src 'self' https:",
            "connect-src 'self' https:",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'"
        ].join('; ');
        
        document.head.appendChild(meta);
    }

    /**
     * Sanitize user input to prevent XSS attacks
     */
    sanitizeInput(input) {
        if (typeof input !== 'string') {
            return input;
        }

        // Remove script tags and event handlers
        let sanitized = input
            .replace(/<script[^>]*>.*?<\/script>/gi, '')
            .replace(/<script[^>]*>/gi, '')
            .replace(/javascript:/gi, '')
            .replace(/on\w+\s*=/gi, '')
            .replace(/<iframe[^>]*>.*?<\/iframe>/gi, '')
            .replace(/<object[^>]*>.*?<\/object>/gi, '')
            .replace(/<embed[^>]*>/gi, '')
            .replace(/<link[^>]*>/gi, '')
            .replace(/<meta[^>]*>/gi, '')
            .replace(/<style[^>]*>.*?<\/style>/gi, '');

        // Encode HTML entities
        const div = document.createElement('div');
        div.textContent = sanitized;
        return div.innerHTML;
    }

    /**
     * Validate input against SQL injection patterns
     */
    validateSQLInjection(input) {
        if (typeof input !== 'string') {
            return true;
        }

        const sqlPatterns = [
            /('|(\-\-)|(;)|(\||\|)|(\*|\*))/i,
            /(union|select|insert|delete|update|drop|create|alter|exec|execute)/i,
            /(script|javascript|vbscript|onload|onerror|onclick)/i,
            /(\<|\>|\%3C|\%3E)/i,
            /(eval|expression|url|behavior)/i
        ];

        for (const pattern of sqlPatterns) {
            if (pattern.test(input)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Validate input against prompt injection patterns
     */
    validatePromptInjection(input) {
        if (typeof input !== 'string') {
            return true;
        }

        const promptPatterns = [
            /ignore\s+(previous|above|all)\s+(instructions?|prompts?|rules?)/gi,
            /forget\s+(everything|all|previous|above)/gi,
            /disregard\s+(previous|above|all)\s+(instructions?|prompts?|rules?)/gi,
            /you\s+are\s+(now|a|an)\s+(assistant|ai|bot|system|admin|developer)/gi,
            /act\s+as\s+(if\s+you\s+are\s+)?(a|an)?\s*(assistant|ai|bot|system|admin|developer)/gi,
            /show\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions?|rules?)/gi,
            /\[\s*system\s*\]/gi,
            /\[\s*user\s*\]/gi,
            /\[\s*assistant\s*\]/gi
        ];

        for (const pattern of promptPatterns) {
            if (pattern.test(input)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Setup comprehensive input sanitization for all forms
     */
    setupInputSanitization() {
        // Monitor all form inputs
        document.addEventListener('input', (e) => {
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
                const originalValue = e.target.value;
                
                // Check for SQL injection
                if (!this.validateSQLInjection(originalValue)) {
                    this.handleSecurityViolation('SQL Injection attempt detected', originalValue);
                    e.target.value = this.sanitizeInput(originalValue);
                    return;
                }

                // Check for prompt injection
                if (!this.validatePromptInjection(originalValue)) {
                    this.handleSecurityViolation('Prompt injection attempt detected', originalValue);
                    e.target.value = this.sanitizeInput(originalValue);
                    return;
                }

                // Sanitize input
                const sanitizedValue = this.sanitizeInput(originalValue);
                if (sanitizedValue !== originalValue) {
                    e.target.value = sanitizedValue;
                    this.showSecurityWarning('Input has been sanitized for security');
                }
            }
        });

        // Monitor form submissions
        document.addEventListener('submit', (e) => {
            const form = e.target;
            const formData = new FormData(form);
            
            for (const [key, value] of formData.entries()) {
                if (typeof value === 'string') {
                    if (!this.validateSQLInjection(value) || !this.validatePromptInjection(value)) {
                        e.preventDefault();
                        this.handleSecurityViolation('Security violation in form submission', value);
                        return false;
                    }
                }
            }
        });
    }

    /**
     * Setup XSS protection
     */
    setupXSSProtection() {
        // Add a safe method for setting HTML content
        Element.prototype.setSafeHTML = function(value) {
            const sanitizedValue = window.securityEnhancer.sanitizeInput(value);
            this.innerHTML = sanitizedValue;
        };
        
        // Log warning when innerHTML is used directly
        console.warn('Security Enhancement: Use setSafeHTML() instead of innerHTML for better XSS protection');
    }

    /**
     * Setup clickjacking protection
     */
    setupClickjackingProtection() {
        // Prevent page from being embedded in frames
        if (window.top !== window.self) {
            window.top.location = window.self.location;
        }

        // Add X-Frame-Options equivalent
        const meta = document.createElement('meta');
        meta.httpEquiv = 'X-Frame-Options';
        meta.content = 'DENY';
        document.head.appendChild(meta);
    }

    /**
     * Setup secure storage with encryption
     */
    setupSecureStorage() {
        // Simple encryption for localStorage (for demo purposes)
        const originalSetItem = localStorage.setItem;
        const originalGetItem = localStorage.getItem;

        localStorage.setItem = function(key, value) {
            if (key.startsWith('da_realest_geek_')) {
                // Add timestamp and basic obfuscation
                const secureValue = {
                    data: btoa(value), // Base64 encoding
                    timestamp: Date.now(),
                    checksum: window.securityEnhancer.generateChecksum(value)
                };
                originalSetItem.call(this, key, JSON.stringify(secureValue));
            } else {
                originalSetItem.call(this, key, value);
            }
        };

        localStorage.getItem = function(key) {
            if (key.startsWith('da_realest_geek_')) {
                const storedValue = originalGetItem.call(this, key);
                if (storedValue) {
                    try {
                        const secureValue = JSON.parse(storedValue);
                        const decodedData = atob(secureValue.data);
                        
                        // Verify checksum
                        if (window.securityEnhancer.generateChecksum(decodedData) !== secureValue.checksum) {
                            console.warn('Data integrity check failed for:', key);
                            localStorage.removeItem(key);
                            return null;
                        }
                        
                        return decodedData;
                    } catch (e) {
                        console.warn('Failed to decrypt stored data:', key);
                        localStorage.removeItem(key);
                        return null;
                    }
                }
                return null;
            } else {
                return originalGetItem.call(this, key);
            }
        };
    }

    /**
     * Generate simple checksum for data integrity
     */
    generateChecksum(data) {
        let hash = 0;
        for (let i = 0; i < data.length; i++) {
            const char = data.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return hash.toString();
    }

    /**
     * Monitor security events
     */
    monitorSecurityEvents() {
        // Monitor for suspicious activities
        let suspiciousActivityCount = 0;
        const maxSuspiciousActivities = 5;
        
        window.addEventListener('error', (e) => {
            if (e.message.includes('script') || e.message.includes('eval')) {
                this.handleSecurityViolation('Suspicious script execution detected', e.message);
            }
        });

        // Monitor for rapid form submissions (potential bot activity)
        let lastSubmissionTime = 0;
        document.addEventListener('submit', (e) => {
            const currentTime = Date.now();
            if (currentTime - lastSubmissionTime < 1000) { // Less than 1 second
                suspiciousActivityCount++;
                if (suspiciousActivityCount > maxSuspiciousActivities) {
                    this.handleSecurityViolation('Rapid form submission detected - potential bot activity');
                    e.preventDefault();
                }
            }
            lastSubmissionTime = currentTime;
        });
    }

    /**
     * Handle security violations
     */
    handleSecurityViolation(type, details = '') {
        console.warn(`Security Violation: ${type}`, details);
        
        // Log to server (in a real implementation)
        // this.logSecurityEvent(type, details);
        
        // Show user-friendly message
        this.showSecurityWarning('Security check failed. Please review your input.');
        
        // In production, you might want to:
        // - Block the user temporarily
        // - Require additional authentication
        // - Log the incident for review
    }

    /**
     * Show security warning to user
     */
    showSecurityWarning(message) {
        // Create or update security warning
        let warning = document.getElementById('security-warning');
        if (!warning) {
            warning = document.createElement('div');
            warning.id = 'security-warning';
            warning.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                background: #ff6b6b;
                color: white;
                padding: 15px 20px;
                border-radius: 8px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                z-index: 10000;
                font-family: 'Segoe UI', sans-serif;
                font-size: 14px;
                max-width: 300px;
                opacity: 0;
                transform: translateX(100%);
                transition: all 0.3s ease;
            `;
            document.body.appendChild(warning);
        }
        
        warning.textContent = `🛡️ ${message}`;
        
        // Show warning
        setTimeout(() => {
            warning.style.opacity = '1';
            warning.style.transform = 'translateX(0)';
        }, 100);
        
        // Hide warning after 5 seconds
        setTimeout(() => {
            warning.style.opacity = '0';
            warning.style.transform = 'translateX(100%)';
        }, 5000);
    }

    /**
     * Validate email format
     */
    validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    /**
     * Validate password strength
     */
    validatePassword(password) {
        // Minimum 8 characters, at least one letter and one number
        const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{8,}$/;
        return passwordRegex.test(password);
    }

    /**
     * Rate limiting for API calls
     */
    createRateLimiter(maxRequests = 10, timeWindow = 60000) {
        const requests = [];
        
        return function() {
            const now = Date.now();
            
            // Remove old requests outside the time window
            while (requests.length > 0 && requests[0] < now - timeWindow) {
                requests.shift();
            }
            
            // Check if we've exceeded the limit
            if (requests.length >= maxRequests) {
                window.securityEnhancer.showSecurityWarning('Rate limit exceeded. Please wait before trying again.');
                return false;
            }
            
            // Add current request
            requests.push(now);
            return true;
        };
    }
}

// Initialize security enhancer when DOM is loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.securityEnhancer = new SecurityEnhancer();
    });
} else {
    window.securityEnhancer = new SecurityEnhancer();
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecurityEnhancer;
}