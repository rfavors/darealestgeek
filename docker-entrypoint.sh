#!/bin/bash

# Docker entrypoint script for daRealestGeek
# This script handles initialization and startup tasks

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Wait for database to be ready
wait_for_database() {
    log_info "Waiting for database to be ready..."
    
    # Extract database connection details from DATABASE_URL
    if [[ -n "$DATABASE_URL" ]]; then
        # Parse DATABASE_URL
        DB_HOST=$(echo $DATABASE_URL | sed -n 's/.*@\([^:]*\):.*/\1/p')
        DB_PORT=$(echo $DATABASE_URL | sed -n 's/.*:\([0-9]*\)\/.*/\1/p')
        DB_USER=$(echo $DATABASE_URL | sed -n 's/.*:\/\/\([^:]*\):.*/\1/p')
        DB_NAME=$(echo $DATABASE_URL | sed -n 's/.*\/\([^?]*\).*/\1/p')
        
        # Default values if parsing fails
        DB_HOST=${DB_HOST:-postgres}
        DB_PORT=${DB_PORT:-5432}
        DB_USER=${DB_USER:-postgres}
        DB_NAME=${DB_NAME:-darealestgeek}
        
        # Wait for database connection
        for i in {1..30}; do
            if pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" > /dev/null 2>&1; then
                log_success "Database is ready!"
                return 0
            fi
            log_info "Waiting for database... (attempt $i/30)"
            sleep 2
        done
        
        log_error "Database is not ready after 60 seconds"
        exit 1
    else
        log_warning "DATABASE_URL not set, skipping database check"
    fi
}

# Wait for Redis to be ready
wait_for_redis() {
    log_info "Waiting for Redis to be ready..."
    
    if [[ -n "$REDIS_URL" ]]; then
        # Extract Redis connection details
        REDIS_HOST=$(echo $REDIS_URL | sed -n 's/.*@\([^:]*\):.*/\1/p')
        REDIS_PORT=$(echo $REDIS_URL | sed -n 's/.*:\([0-9]*\)$/\1/p')
        
        # Default values
        REDIS_HOST=${REDIS_HOST:-redis}
        REDIS_PORT=${REDIS_PORT:-6379}
        
        # Wait for Redis connection
        for i in {1..30}; do
            if redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ping > /dev/null 2>&1; then
                log_success "Redis is ready!"
                return 0
            fi
            log_info "Waiting for Redis... (attempt $i/30)"
            sleep 2
        done
        
        log_error "Redis is not ready after 60 seconds"
        exit 1
    else
        log_warning "REDIS_URL not set, skipping Redis check"
    fi
}

# Generate Prisma client if needed
generate_prisma_client() {
    log_info "Generating Prisma client..."
    
    cd /app/packages/database
    
    if [[ -f "prisma/schema.prisma" ]]; then
        npx prisma generate
        log_success "Prisma client generated successfully"
    else
        log_warning "Prisma schema not found, skipping client generation"
    fi
    
    cd /app
}

# Run database migrations
run_migrations() {
    log_info "Running database migrations..."
    
    cd /app/packages/database
    
    if [[ -f "prisma/schema.prisma" ]]; then
        # Run migrations
        npx prisma migrate deploy
        log_success "Database migrations completed"
        
        # Seed database if SEED_DATABASE is true
        if [[ "${SEED_DATABASE:-false}" == "true" ]]; then
            log_info "Seeding database..."
            npm run db:seed
            log_success "Database seeded successfully"
        fi
    else
        log_warning "Prisma schema not found, skipping migrations"
    fi
    
    cd /app
}

# Setup log directories
setup_logging() {
    log_info "Setting up logging directories..."
    
    # Create log directories
    mkdir -p /var/log/supervisor
    mkdir -p /var/log/nginx
    mkdir -p /app/logs
    
    # Set permissions
    chown -R nextjs:nodejs /var/log/supervisor
    chown -R nextjs:nodejs /app/logs
    
    log_success "Logging directories configured"
}

# Setup SSL certificates if needed
setup_ssl() {
    if [[ "${SSL_ENABLED:-true}" == "true" ]]; then
        log_info "Setting up SSL certificates..."
        
        # Create SSL directory
        mkdir -p /etc/nginx/ssl
        
        # Check if certificates exist
        if [[ ! -f "/etc/nginx/ssl/cert.pem" ]] || [[ ! -f "/etc/nginx/ssl/key.pem" ]]; then
            log_warning "SSL certificates not found, generating self-signed certificates..."
            
            # Generate self-signed certificate
            openssl req -x509 -newkey rsa:4096 -keyout /etc/nginx/ssl/key.pem -out /etc/nginx/ssl/cert.pem -days 365 -nodes -subj "/CN=${DOMAIN_NAME:-localhost}"
            
            log_success "Self-signed SSL certificates generated"
        else
            log_success "SSL certificates found"
        fi
        
        # Set permissions
        chmod 600 /etc/nginx/ssl/key.pem
        chmod 644 /etc/nginx/ssl/cert.pem
    else
        log_info "SSL disabled, skipping certificate setup"
    fi
}

# Validate environment variables
validate_environment() {
    log_info "Validating environment variables..."
    
    # Required variables
    required_vars=(
        "NODE_ENV"
        "DATABASE_URL"
    )
    
    missing_vars=()
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var}" ]]; then
            missing_vars+=("$var")
        fi
    done
    
    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        log_error "Missing required environment variables:"
        printf '%s\n' "${missing_vars[@]}"
        exit 1
    fi
    
    # Warn about optional but recommended variables
    recommended_vars=(
        "OPENAI_API_KEY"
        "STRIPE_SECRET_KEY"
        "SENDGRID_API_KEY"
        "TWILIO_ACCOUNT_SID"
    )
    
    missing_recommended=()
    
    for var in "${recommended_vars[@]}"; do
        if [[ -z "${!var}" ]]; then
            missing_recommended+=("$var")
        fi
    done
    
    if [[ ${#missing_recommended[@]} -gt 0 ]]; then
        log_warning "Missing recommended environment variables (some features may not work):"
        printf '%s\n' "${missing_recommended[@]}"
    fi
    
    log_success "Environment validation completed"
}

# Health check function
health_check() {
    log_info "Running initial health check..."
    
    # Check if required directories exist
    if [[ ! -d "/app/apps/web" ]] || [[ ! -d "/app/apps/api" ]]; then
        log_error "Application directories not found"
        exit 1
    fi
    
    # Check if node_modules exist
    if [[ ! -d "/app/node_modules" ]]; then
        log_error "Node modules not found"
        exit 1
    fi
    
    log_success "Health check passed"
}

# Cleanup function for graceful shutdown
cleanup() {
    log_info "Shutting down gracefully..."
    
    # Stop supervisor and all child processes
    if [[ -f "/var/run/supervisord.pid" ]]; then
        supervisorctl shutdown
    fi
    
    log_success "Shutdown completed"
    exit 0
}

# Set up signal handlers
trap cleanup SIGTERM SIGINT

# Main initialization function
main() {
    log_info "Starting daRealestGeek application..."
    
    # Run initialization steps
    validate_environment
    health_check
    setup_logging
    setup_ssl
    wait_for_database
    wait_for_redis
    generate_prisma_client
    run_migrations
    
    log_success "Initialization completed successfully!"
    log_info "Starting application services..."
    
    # Execute the main command
    exec "$@"
}

# Run main function
main "$@"