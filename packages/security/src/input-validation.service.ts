/**
 * Input Validation Service
 * Provides comprehensive input validation and sanitization
 */

import { Injectable, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import validator from 'validator';
import DOMPurify from 'isomorphic-dompurify';
import { Logger } from '@nestjs/common';

export interface ValidationRule {
  required?: boolean;
  minLength?: number;
  maxLength?: number;
  pattern?: RegExp;
  type?: 'string' | 'number' | 'email' | 'url' | 'uuid' | 'date' | 'boolean' | 'array' | 'object';
  allowedValues?: any[];
  customValidator?: (value: any) => boolean | string;
  sanitize?: boolean;
  allowHtml?: boolean;
}

export interface ValidationSchema {
  [key: string]: ValidationRule;
}

export interface ValidationResult {
  isValid: boolean;
  errors: string[];
  sanitizedData: any;
}

@Injectable()
export class InputValidationService {
  private readonly logger = new Logger(InputValidationService.name);
  
  // Common validation patterns
  private readonly patterns = {
    alphanumeric: /^[a-zA-Z0-9]+$/,
    alphanumericWithSpaces: /^[a-zA-Z0-9\s]+$/,
    alphanumericWithSpecial: /^[a-zA-Z0-9\s\-_\.]+$/,
    phoneNumber: /^[\+]?[1-9][\d]{0,15}$/,
    strongPassword: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
    slug: /^[a-z0-9]+(?:-[a-z0-9]+)*$/,
    hexColor: /^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/,
    ipAddress: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
    macAddress: /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/,
    creditCard: /^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})$/,
    base64: /^[A-Za-z0-9+/]*={0,2}$/,
    jwt: /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/,
    mongoObjectId: /^[0-9a-fA-F]{24}$/,
    semver: /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/
  };
  
  // Dangerous HTML tags and attributes
  private readonly dangerousHtmlTags = [
    'script', 'iframe', 'object', 'embed', 'form', 'input', 'textarea',
    'button', 'select', 'option', 'link', 'meta', 'style', 'base',
    'applet', 'bgsound', 'blink', 'body', 'frame', 'frameset',
    'head', 'html', 'ilayer', 'layer', 'marquee', 'plaintext',
    'xml', 'xmp'
  ];
  
  private readonly dangerousHtmlAttributes = [
    'onabort', 'onactivate', 'onafterprint', 'onafterupdate', 'onbeforeactivate',
    'onbeforecopy', 'onbeforecut', 'onbeforedeactivate', 'onbeforeeditfocus',
    'onbeforepaste', 'onbeforeprint', 'onbeforeunload', 'onbeforeupdate',
    'onblur', 'onbounce', 'oncellchange', 'onchange', 'onclick', 'oncontextmenu',
    'oncontrolselect', 'oncopy', 'oncut', 'ondataavailable', 'ondatasetchanged',
    'ondatasetcomplete', 'ondblclick', 'ondeactivate', 'ondrag', 'ondragend',
    'ondragenter', 'ondragleave', 'ondragover', 'ondragstart', 'ondrop',
    'onerror', 'onerrorupdate', 'onfilterchange', 'onfinish', 'onfocus',
    'onfocusin', 'onfocusout', 'onhelp', 'onkeydown', 'onkeypress', 'onkeyup',
    'onlayoutcomplete', 'onload', 'onlosecapture', 'onmousedown', 'onmouseenter',
    'onmouseleave', 'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup',
    'onmousewheel', 'onmove', 'onmoveend', 'onmovestart', 'onpaste',
    'onpropertychange', 'onreadystatechange', 'onreset', 'onresize',
    'onresizeend', 'onresizestart', 'onrowenter', 'onrowexit', 'onrowsdelete',
    'onrowsinserted', 'onscroll', 'onselect', 'onselectionchange',
    'onselectstart', 'onstart', 'onstop', 'onsubmit', 'onunload', 'javascript:',
    'vbscript:', 'data:', 'expression('
  ];
  
  constructor(private configService: ConfigService) {}
  
  /**
   * Validate input data against a schema
   */
  validateInput(data: any, schema: ValidationSchema): ValidationResult {
    const errors: string[] = [];
    const sanitizedData: any = {};
    
    try {
      // Validate each field in the schema
      for (const [fieldName, rule] of Object.entries(schema)) {
        const value = data[fieldName];
        const fieldResult = this.validateField(fieldName, value, rule);
        
        if (!fieldResult.isValid) {
          errors.push(...fieldResult.errors);
        } else {
          sanitizedData[fieldName] = fieldResult.sanitizedValue;
        }
      }
      
      // Check for unexpected fields
      const allowedFields = Object.keys(schema);
      const providedFields = Object.keys(data || {});
      const unexpectedFields = providedFields.filter(field => !allowedFields.includes(field));
      
      if (unexpectedFields.length > 0) {
        this.logger.warn(`Unexpected fields in input: ${unexpectedFields.join(', ')}`);
        // Don't add unexpected fields to sanitized data
      }
      
      return {
        isValid: errors.length === 0,
        errors,
        sanitizedData
      };
    } catch (error) {
      this.logger.error('Error during input validation', error);
      return {
        isValid: false,
        errors: ['Validation failed due to internal error'],
        sanitizedData: {}
      };
    }
  }
  
  /**
   * Validate a single field
   */
  private validateField(fieldName: string, value: any, rule: ValidationRule): { isValid: boolean; errors: string[]; sanitizedValue: any } {
    const errors: string[] = [];
    let sanitizedValue = value;
    
    // Check if field is required
    if (rule.required && (value === undefined || value === null || value === '')) {
      errors.push(`${fieldName} is required`);
      return { isValid: false, errors, sanitizedValue: null };
    }
    
    // If value is empty and not required, return early
    if (!rule.required && (value === undefined || value === null || value === '')) {
      return { isValid: true, errors: [], sanitizedValue: null };
    }
    
    // Type validation and conversion
    const typeResult = this.validateType(fieldName, value, rule.type || 'string');
    if (!typeResult.isValid) {
      errors.push(...typeResult.errors);
      return { isValid: false, errors, sanitizedValue };
    }
    sanitizedValue = typeResult.convertedValue;
    
    // String-specific validations
    if (rule.type === 'string' || !rule.type) {
      const stringResult = this.validateString(fieldName, sanitizedValue, rule);
      if (!stringResult.isValid) {
        errors.push(...stringResult.errors);
      }
      sanitizedValue = stringResult.sanitizedValue;
    }
    
    // Pattern validation
    if (rule.pattern && typeof sanitizedValue === 'string') {
      if (!rule.pattern.test(sanitizedValue)) {
        errors.push(`${fieldName} does not match the required pattern`);
      }
    }
    
    // Allowed values validation
    if (rule.allowedValues && !rule.allowedValues.includes(sanitizedValue)) {
      errors.push(`${fieldName} must be one of: ${rule.allowedValues.join(', ')}`);
    }
    
    // Custom validation
    if (rule.customValidator) {
      const customResult = rule.customValidator(sanitizedValue);
      if (customResult !== true) {
        errors.push(typeof customResult === 'string' ? customResult : `${fieldName} failed custom validation`);
      }
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      sanitizedValue
    };
  }
  
  /**
   * Validate and convert type
   */
  private validateType(fieldName: string, value: any, type: string): { isValid: boolean; errors: string[]; convertedValue: any } {
    const errors: string[] = [];
    let convertedValue = value;
    
    switch (type) {
      case 'string':
        if (typeof value !== 'string') {
          convertedValue = String(value);
        }
        break;
        
      case 'number':
        if (typeof value === 'string') {
          const parsed = parseFloat(value);
          if (isNaN(parsed) || !isFinite(parsed)) {
            errors.push(`${fieldName} must be a valid number`);
          } else {
            convertedValue = parsed;
          }
        } else if (typeof value !== 'number' || isNaN(value) || !isFinite(value)) {
          errors.push(`${fieldName} must be a valid number`);
        }
        break;
        
      case 'boolean':
        if (typeof value === 'string') {
          const lower = value.toLowerCase().trim();
          convertedValue = lower === 'true' || lower === '1' || lower === 'yes';
        } else if (typeof value !== 'boolean') {
          convertedValue = Boolean(value);
        }
        break;
        
      case 'email':
        if (typeof value !== 'string' || !validator.isEmail(value)) {
          errors.push(`${fieldName} must be a valid email address`);
        } else {
          convertedValue = value.toLowerCase().trim();
        }
        break;
        
      case 'url':
        if (typeof value !== 'string' || !validator.isURL(value, { require_protocol: true })) {
          errors.push(`${fieldName} must be a valid URL`);
        }
        break;
        
      case 'uuid':
        if (typeof value !== 'string' || !validator.isUUID(value)) {
          errors.push(`${fieldName} must be a valid UUID`);
        }
        break;
        
      case 'date':
        if (typeof value === 'string') {
          const date = new Date(value);
          if (isNaN(date.getTime())) {
            errors.push(`${fieldName} must be a valid date`);
          } else {
            convertedValue = date;
          }
        } else if (!(value instanceof Date) || isNaN(value.getTime())) {
          errors.push(`${fieldName} must be a valid date`);
        }
        break;
        
      case 'array':
        if (!Array.isArray(value)) {
          errors.push(`${fieldName} must be an array`);
        }
        break;
        
      case 'object':
        if (typeof value !== 'object' || value === null || Array.isArray(value)) {
          errors.push(`${fieldName} must be an object`);
        }
        break;
        
      default:
        // Unknown type, treat as string
        if (typeof value !== 'string') {
          convertedValue = String(value);
        }
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      convertedValue
    };
  }
  
  /**
   * Validate string-specific rules
   */
  private validateString(fieldName: string, value: string, rule: ValidationRule): { isValid: boolean; errors: string[]; sanitizedValue: string } {
    const errors: string[] = [];
    let sanitizedValue = value;
    
    // Length validation
    if (rule.minLength !== undefined && value.length < rule.minLength) {
      errors.push(`${fieldName} must be at least ${rule.minLength} characters long`);
    }
    
    if (rule.maxLength !== undefined && value.length > rule.maxLength) {
      errors.push(`${fieldName} must be no more than ${rule.maxLength} characters long`);
    }
    
    // Sanitization
    if (rule.sanitize !== false) {
      sanitizedValue = this.sanitizeString(value, rule.allowHtml || false);
    }
    
    // Check for dangerous content after sanitization
    if (!rule.allowHtml && this.containsDangerousHtml(sanitizedValue)) {
      errors.push(`${fieldName} contains potentially dangerous content`);
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      sanitizedValue
    };
  }
  
  /**
   * Sanitize string input
   */
  sanitizeString(input: string, allowHtml: boolean = false): string {
    if (!input || typeof input !== 'string') {
      return '';
    }
    
    let sanitized = input;
    
    // Remove null bytes and control characters
    sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
    
    // Normalize whitespace
    sanitized = sanitized.replace(/\s+/g, ' ').trim();
    
    if (allowHtml) {
      // Use DOMPurify for HTML sanitization
      sanitized = DOMPurify.sanitize(sanitized, {
        ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li', 'a', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'],
        ALLOWED_ATTR: ['href', 'title', 'target'],
        ALLOW_DATA_ATTR: false,
        FORBID_TAGS: this.dangerousHtmlTags,
        FORBID_ATTR: this.dangerousHtmlAttributes
      });
    } else {
      // Escape HTML entities
      sanitized = validator.escape(sanitized);
    }
    
    return sanitized;
  }
  
  /**
   * Check if string contains dangerous HTML
   */
  private containsDangerousHtml(input: string): boolean {
    const lowerInput = input.toLowerCase();
    
    // Check for dangerous tags
    for (const tag of this.dangerousHtmlTags) {
      if (lowerInput.includes(`<${tag}`) || lowerInput.includes(`</${tag}`)) {
        return true;
      }
    }
    
    // Check for dangerous attributes
    for (const attr of this.dangerousHtmlAttributes) {
      if (lowerInput.includes(attr)) {
        return true;
      }
    }
    
    // Check for javascript: and data: URLs
    if (lowerInput.includes('javascript:') || lowerInput.includes('data:') || lowerInput.includes('vbscript:')) {
      return true;
    }
    
    return false;
  }
  
  /**
   * Get validation pattern by name
   */
  getPattern(name: string): RegExp | undefined {
    return this.patterns[name as keyof typeof this.patterns];
  }
  
  /**
   * Validate file upload
   */
  validateFileUpload(file: any, options: {
    maxSize?: number;
    allowedMimeTypes?: string[];
    allowedExtensions?: string[];
    requireExtension?: boolean;
  } = {}): ValidationResult {
    const errors: string[] = [];
    
    if (!file) {
      errors.push('File is required');
      return { isValid: false, errors, sanitizedData: null };
    }
    
    // Check file size
    if (options.maxSize && file.size > options.maxSize) {
      errors.push(`File size must be less than ${Math.round(options.maxSize / 1024 / 1024)}MB`);
    }
    
    // Check MIME type
    if (options.allowedMimeTypes && !options.allowedMimeTypes.includes(file.mimetype)) {
      errors.push(`File type ${file.mimetype} is not allowed`);
    }
    
    // Check file extension
    if (options.allowedExtensions || options.requireExtension) {
      const extension = file.originalname?.split('.').pop()?.toLowerCase();
      
      if (options.requireExtension && !extension) {
        errors.push('File must have an extension');
      }
      
      if (options.allowedExtensions && extension && !options.allowedExtensions.includes(extension)) {
        errors.push(`File extension .${extension} is not allowed`);
      }
    }
    
    // Sanitize filename
    const sanitizedFilename = file.originalname
      ? file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_')
      : 'unnamed_file';
    
    return {
      isValid: errors.length === 0,
      errors,
      sanitizedData: {
        ...file,
        originalname: sanitizedFilename
      }
    };
  }
  
  /**
   * Validate pagination parameters
   */
  validatePagination(page?: any, limit?: any, maxLimit: number = 100): {
    page: number;
    limit: number;
    offset: number;
  } {
    const validatedPage = Math.max(1, parseInt(page) || 1);
    const validatedLimit = Math.min(maxLimit, Math.max(1, parseInt(limit) || 10));
    const offset = (validatedPage - 1) * validatedLimit;
    
    return {
      page: validatedPage,
      limit: validatedLimit,
      offset
    };
  }
  
  /**
   * Validate sort parameters
   */
  validateSort(sort?: string, allowedFields: string[] = []): {
    field: string;
    direction: 'ASC' | 'DESC';
  } | null {
    if (!sort || typeof sort !== 'string') {
      return null;
    }
    
    const [field, direction] = sort.split(':');
    
    if (!field || (allowedFields.length > 0 && !allowedFields.includes(field))) {
      return null;
    }
    
    const validDirection = direction?.toUpperCase() === 'DESC' ? 'DESC' : 'ASC';
    
    return {
      field: field.replace(/[^a-zA-Z0-9_]/g, ''), // Sanitize field name
      direction: validDirection
    };
  }
  
  /**
   * Create a validation error response
   */
  createValidationError(errors: string[]): BadRequestException {
    return new BadRequestException({
      message: 'Validation failed',
      errors,
      code: 'VALIDATION_ERROR',
      timestamp: new Date().toISOString()
    });
  }
}

/**
 * Common validation schemas
 */
export const CommonValidationSchemas = {
  user: {
    email: {
      required: true,
      type: 'email' as const,
      maxLength: 254
    },
    password: {
      required: true,
      type: 'string' as const,
      minLength: 8,
      maxLength: 128,
      pattern: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/
    },
    firstName: {
      required: true,
      type: 'string' as const,
      minLength: 1,
      maxLength: 50,
      pattern: /^[a-zA-Z\s\-']+$/
    },
    lastName: {
      required: true,
      type: 'string' as const,
      minLength: 1,
      maxLength: 50,
      pattern: /^[a-zA-Z\s\-']+$/
    },
    phone: {
      required: false,
      type: 'string' as const,
      pattern: /^[\+]?[1-9][\d]{0,15}$/
    }
  },
  
  lead: {
    email: {
      required: true,
      type: 'email' as const,
      maxLength: 254
    },
    firstName: {
      required: true,
      type: 'string' as const,
      minLength: 1,
      maxLength: 50
    },
    lastName: {
      required: true,
      type: 'string' as const,
      minLength: 1,
      maxLength: 50
    },
    company: {
      required: false,
      type: 'string' as const,
      maxLength: 100
    },
    phone: {
      required: false,
      type: 'string' as const,
      pattern: /^[\+]?[1-9][\d]{0,15}$/
    },
    source: {
      required: false,
      type: 'string' as const,
      allowedValues: ['website', 'social', 'referral', 'advertising', 'other']
    }
  },
  
  document: {
    title: {
      required: true,
      type: 'string' as const,
      minLength: 1,
      maxLength: 200
    },
    content: {
      required: false,
      type: 'string' as const,
      maxLength: 50000,
      allowHtml: true
    },
    tags: {
      required: false,
      type: 'array' as const
    }
  }
};