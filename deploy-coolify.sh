#!/bin/bash

# daRealestGeek Coolify Deployment Script
# This script handles the deployment process for Coolify VPS

set -e  # Exit on any error

echo "🚀 Starting daRealestGeek deployment for Coolify..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if required environment variables are set
check_env_vars() {
    print_status "Checking required environment variables..."
    
    required_vars=(
        "DATABASE_PASSWORD"
        "REDIS_PASSWORD"
        "JWT_SECRET"
        "OPENAI_API_KEY"
        "NEXT_PUBLIC_APP_URL"
        "DOMAIN_NAME"
    )
    
    missing_vars=()
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var}" ]]; then
            missing_vars+=("$var")
        fi
    done
    
    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        print_error "Missing required environment variables:"
        printf '%s\n' "${missing_vars[@]}"
        print_error "Please set these variables in your Coolify environment settings."
        exit 1
    fi
    
    print_success "All required environment variables are set."
}

# Pre-deployment checks
pre_deployment_checks() {
    print_status "Running pre-deployment checks..."
    
    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    # Check if docker-compose is available
    if ! command -v docker-compose &> /dev/null; then
        print_error "docker-compose is not installed or not in PATH"
        exit 1
    fi
    
    print_success "Pre-deployment checks passed."
}

# Build and deploy services
deploy_services() {
    print_status "Building and deploying services..."
    
    # Pull latest images
    print_status "Pulling base images..."
    docker-compose pull postgres redis nginx
    
    # Build custom images
    print_status "Building application images..."
    docker-compose build --no-cache api web
    
    # Start services
    print_status "Starting services..."
    docker-compose up -d
    
    print_success "Services deployed successfully."
}

# Wait for services to be healthy
wait_for_services() {
    print_status "Waiting for services to be healthy..."
    
    # Wait for database
    print_status "Waiting for PostgreSQL..."
    timeout 60 bash -c 'until docker-compose exec -T postgres pg_isready -U ${DATABASE_USER:-postgres}; do sleep 2; done'
    
    # Wait for Redis
    print_status "Waiting for Redis..."
    timeout 60 bash -c 'until docker-compose exec -T redis redis-cli ping; do sleep 2; done'
    
    # Wait for API
    print_status "Waiting for API service..."
    timeout 120 bash -c 'until curl -f http://localhost:3001/health; do sleep 5; done'
    
    # Wait for Web
    print_status "Waiting for Web service..."
    timeout 120 bash -c 'until curl -f http://localhost:3000; do sleep 5; done'
    
    print_success "All services are healthy."
}

# Run database migrations
run_migrations() {
    print_status "Running database migrations..."
    
    # Run Prisma migrations
    docker-compose exec -T api npm run db:migrate:deploy
    
    # Seed database if needed
    if [[ "${SEED_DATABASE:-false}" == "true" ]]; then
        print_status "Seeding database..."
        docker-compose exec -T api npm run db:seed
    fi
    
    print_success "Database migrations completed."
}

# Setup SSL certificates (if not handled by Coolify)
setup_ssl() {
    if [[ "${COOLIFY_SSL_MANAGED:-true}" == "false" ]]; then
        print_status "Setting up SSL certificates..."
        
        # Create SSL directory if it doesn't exist
        mkdir -p ./ssl
        
        # Generate self-signed certificates for development
        if [[ ! -f ./ssl/cert.pem ]] || [[ ! -f ./ssl/key.pem ]]; then
            print_warning "Generating self-signed SSL certificates for development..."
            openssl req -x509 -newkey rsa:4096 -keyout ./ssl/key.pem -out ./ssl/cert.pem -days 365 -nodes -subj "/CN=${DOMAIN_NAME:-localhost}"
        fi
        
        print_success "SSL certificates are ready."
    else
        print_status "SSL is managed by Coolify, skipping certificate setup."
    fi
}

# Post-deployment tasks
post_deployment() {
    print_status "Running post-deployment tasks..."
    
    # Clear application caches
    print_status "Clearing application caches..."
    docker-compose exec -T redis redis-cli FLUSHDB
    
    # Restart services to ensure clean state
    print_status "Restarting services..."
    docker-compose restart api web
    
    # Run health checks
    print_status "Running final health checks..."
    sleep 10
    
    # Check API health
    if curl -f http://localhost:3001/health > /dev/null 2>&1; then
        print_success "API service is healthy."
    else
        print_error "API service health check failed."
        exit 1
    fi
    
    # Check Web health
    if curl -f http://localhost:3000 > /dev/null 2>&1; then
        print_success "Web service is healthy."
    else
        print_error "Web service health check failed."
        exit 1
    fi
    
    print_success "Post-deployment tasks completed."
}

# Cleanup old images and containers
cleanup() {
    print_status "Cleaning up old Docker images and containers..."
    
    # Remove unused images
    docker image prune -f
    
    # Remove unused containers
    docker container prune -f
    
    # Remove unused volumes (be careful with this in production)
    if [[ "${CLEANUP_VOLUMES:-false}" == "true" ]]; then
        print_warning "Cleaning up unused volumes..."
        docker volume prune -f
    fi
    
    print_success "Cleanup completed."
}

# Main deployment function
main() {
    print_status "Starting daRealestGeek deployment..."
    
    check_env_vars
    pre_deployment_checks
    setup_ssl
    deploy_services
    wait_for_services
    run_migrations
    post_deployment
    cleanup
    
    print_success "🎉 Deployment completed successfully!"
    print_status "Your application is now available at: https://${DOMAIN_NAME:-localhost}"
    print_status "API endpoint: https://${DOMAIN_NAME:-localhost}/api"
    
    # Display service status
    echo ""
    print_status "Service Status:"
    docker-compose ps
}

# Handle script interruption
trap 'print_error "Deployment interrupted. Cleaning up..."; docker-compose down; exit 1' INT TERM

# Run main function
main "$@"