#!/bin/bash

# Health check script for daRealestGeek
# This script monitors all services and provides detailed status information

set -e

# Configuration
HEALTH_CHECK_INTERVAL=${HEALTH_CHECK_INTERVAL:-30}
MAX_RETRIES=${MAX_RETRIES:-3}
TIMEOUT=${TIMEOUT:-10}
LOG_FILE="/var/log/supervisor/healthcheck.log"

# Service endpoints
WEB_URL="http://localhost:3000"
API_URL="http://localhost:3001"
API_HEALTH_URL="http://localhost:3001/health"
API_METRICS_URL="http://localhost:3001/metrics"

# Database and Redis configuration
DB_HOST=${DB_HOST:-postgres}
DB_PORT=${DB_PORT:-5432}
DB_USER=${DB_USER:-postgres}
REDIS_HOST=${REDIS_HOST:-redis}
REDIS_PORT=${REDIS_PORT:-6379}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

# Health check functions
check_web_service() {
    local retries=0
    
    while [[ $retries -lt $MAX_RETRIES ]]; do
        if curl -f -s --max-time "$TIMEOUT" "$WEB_URL" > /dev/null 2>&1; then
            log_success "Web service is healthy"
            return 0
        fi
        
        retries=$((retries + 1))
        log_warning "Web service check failed (attempt $retries/$MAX_RETRIES)"
        
        if [[ $retries -lt $MAX_RETRIES ]]; then
            sleep 5
        fi
    done
    
    log_error "Web service is unhealthy after $MAX_RETRIES attempts"
    return 1
}

check_api_service() {
    local retries=0
    
    while [[ $retries -lt $MAX_RETRIES ]]; do
        if curl -f -s --max-time "$TIMEOUT" "$API_HEALTH_URL" > /dev/null 2>&1; then
            log_success "API service is healthy"
            return 0
        fi
        
        retries=$((retries + 1))
        log_warning "API service check failed (attempt $retries/$MAX_RETRIES)"
        
        if [[ $retries -lt $MAX_RETRIES ]]; then
            sleep 5
        fi
    done
    
    log_error "API service is unhealthy after $MAX_RETRIES attempts"
    return 1
}

check_database() {
    local retries=0
    
    while [[ $retries -lt $MAX_RETRIES ]]; do
        if pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -t "$TIMEOUT" > /dev/null 2>&1; then
            log_success "Database is healthy"
            return 0
        fi
        
        retries=$((retries + 1))
        log_warning "Database check failed (attempt $retries/$MAX_RETRIES)"
        
        if [[ $retries -lt $MAX_RETRIES ]]; then
            sleep 5
        fi
    done
    
    log_error "Database is unhealthy after $MAX_RETRIES attempts"
    return 1
}

check_redis() {
    local retries=0
    
    while [[ $retries -lt $MAX_RETRIES ]]; do
        if timeout "$TIMEOUT" redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ping > /dev/null 2>&1; then
            log_success "Redis is healthy"
            return 0
        fi
        
        retries=$((retries + 1))
        log_warning "Redis check failed (attempt $retries/$MAX_RETRIES)"
        
        if [[ $retries -lt $MAX_RETRIES ]]; then
            sleep 5
        fi
    done
    
    log_error "Redis is unhealthy after $MAX_RETRIES attempts"
    return 1
}

check_disk_space() {
    local threshold=90
    local usage
    
    usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    
    if [[ $usage -gt $threshold ]]; then
        log_error "Disk usage is critical: ${usage}%"
        return 1
    elif [[ $usage -gt 80 ]]; then
        log_warning "Disk usage is high: ${usage}%"
    else
        log_success "Disk usage is normal: ${usage}%"
    fi
    
    return 0
}

check_memory_usage() {
    local threshold=90
    local usage
    
    usage=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
    
    if [[ $usage -gt $threshold ]]; then
        log_error "Memory usage is critical: ${usage}%"
        return 1
    elif [[ $usage -gt 80 ]]; then
        log_warning "Memory usage is high: ${usage}%"
    else
        log_success "Memory usage is normal: ${usage}%"
    fi
    
    return 0
}

check_cpu_usage() {
    local threshold=90
    local usage
    
    # Get CPU usage over 5 seconds
    usage=$(top -bn2 -d1 | grep "Cpu(s)" | tail -1 | awk '{print $2}' | sed 's/%us,//')
    
    if (( $(echo "$usage > $threshold" | bc -l) )); then
        log_error "CPU usage is critical: ${usage}%"
        return 1
    elif (( $(echo "$usage > 80" | bc -l) )); then
        log_warning "CPU usage is high: ${usage}%"
    else
        log_success "CPU usage is normal: ${usage}%"
    fi
    
    return 0
}

check_ssl_certificate() {
    local domain=${DOMAIN_NAME:-localhost}
    local cert_file="/etc/nginx/ssl/cert.pem"
    
    if [[ -f "$cert_file" ]]; then
        local expiry_date
        local days_until_expiry
        
        expiry_date=$(openssl x509 -enddate -noout -in "$cert_file" | cut -d= -f2)
        days_until_expiry=$(( ($(date -d "$expiry_date" +%s) - $(date +%s)) / 86400 ))
        
        if [[ $days_until_expiry -lt 7 ]]; then
            log_error "SSL certificate expires in $days_until_expiry days"
            return 1
        elif [[ $days_until_expiry -lt 30 ]]; then
            log_warning "SSL certificate expires in $days_until_expiry days"
        else
            log_success "SSL certificate is valid for $days_until_expiry days"
        fi
    else
        log_warning "SSL certificate file not found"
    fi
    
    return 0
}

check_external_apis() {
    local apis_healthy=true
    
    # Check OpenAI API
    if [[ -n "$OPENAI_API_KEY" ]]; then
        if curl -f -s --max-time "$TIMEOUT" \
            -H "Authorization: Bearer $OPENAI_API_KEY" \
            "https://api.openai.com/v1/models" > /dev/null 2>&1; then
            log_success "OpenAI API is accessible"
        else
            log_error "OpenAI API is not accessible"
            apis_healthy=false
        fi
    fi
    
    # Check Stripe API
    if [[ -n "$STRIPE_SECRET_KEY" ]]; then
        if curl -f -s --max-time "$TIMEOUT" \
            -u "$STRIPE_SECRET_KEY:" \
            "https://api.stripe.com/v1/account" > /dev/null 2>&1; then
            log_success "Stripe API is accessible"
        else
            log_error "Stripe API is not accessible"
            apis_healthy=false
        fi
    fi
    
    # Check SendGrid API
    if [[ -n "$SENDGRID_API_KEY" ]]; then
        if curl -f -s --max-time "$TIMEOUT" \
            -H "Authorization: Bearer $SENDGRID_API_KEY" \
            "https://api.sendgrid.com/v3/user/account" > /dev/null 2>&1; then
            log_success "SendGrid API is accessible"
        else
            log_error "SendGrid API is not accessible"
            apis_healthy=false
        fi
    fi
    
    if [[ "$apis_healthy" == "true" ]]; then
        return 0
    else
        return 1
    fi
}

get_service_metrics() {
    log_info "Collecting service metrics..."
    
    # API metrics
    if curl -f -s --max-time "$TIMEOUT" "$API_METRICS_URL" > /tmp/api_metrics.json 2>/dev/null; then
        log_success "API metrics collected"
    else
        log_warning "Failed to collect API metrics"
    fi
    
    # System metrics
    echo "System Metrics:" >> "$LOG_FILE"
    echo "- Uptime: $(uptime)" >> "$LOG_FILE"
    echo "- Load Average: $(cat /proc/loadavg)" >> "$LOG_FILE"
    echo "- Memory: $(free -h | grep Mem)" >> "$LOG_FILE"
    echo "- Disk: $(df -h /)" >> "$LOG_FILE"
}

send_alert() {
    local message="$1"
    local severity="$2"
    
    # Send to webhook if configured
    if [[ -n "$ALERT_WEBHOOK_URL" ]]; then
        curl -X POST "$ALERT_WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "{
                \"text\": \"$message\",
                \"severity\": \"$severity\",
                \"timestamp\": \"$(date -Iseconds)\",
                \"service\": \"daRealestGeek\"
            }" > /dev/null 2>&1
    fi
    
    # Log the alert
    if [[ "$severity" == "critical" ]]; then
        log_error "ALERT: $message"
    else
        log_warning "ALERT: $message"
    fi
}

# Main health check function
run_health_checks() {
    local overall_health=true
    local failed_checks=()
    
    log_info "Starting health check cycle..."
    
    # Core service checks
    if ! check_web_service; then
        overall_health=false
        failed_checks+=("Web Service")
    fi
    
    if ! check_api_service; then
        overall_health=false
        failed_checks+=("API Service")
    fi
    
    if ! check_database; then
        overall_health=false
        failed_checks+=("Database")
    fi
    
    if ! check_redis; then
        overall_health=false
        failed_checks+=("Redis")
    fi
    
    # System resource checks
    if ! check_disk_space; then
        overall_health=false
        failed_checks+=("Disk Space")
    fi
    
    if ! check_memory_usage; then
        overall_health=false
        failed_checks+=("Memory Usage")
    fi
    
    if ! check_cpu_usage; then
        overall_health=false
        failed_checks+=("CPU Usage")
    fi
    
    # SSL certificate check
    check_ssl_certificate
    
    # External API checks (non-critical)
    check_external_apis
    
    # Collect metrics
    get_service_metrics
    
    # Send alerts if needed
    if [[ "$overall_health" == "false" ]]; then
        local failed_list=$(IFS=', '; echo "${failed_checks[*]}")
        send_alert "Health check failed for: $failed_list" "critical"
        log_error "Overall health check FAILED. Failed services: $failed_list"
        return 1
    else
        log_success "All health checks PASSED"
        return 0
    fi
}

# Continuous monitoring mode
continuous_monitoring() {
    log_info "Starting continuous health monitoring (interval: ${HEALTH_CHECK_INTERVAL}s)"
    
    while true; do
        run_health_checks
        sleep "$HEALTH_CHECK_INTERVAL"
    done
}

# Main function
main() {
    # Create log directory if it doesn't exist
    mkdir -p "$(dirname "$LOG_FILE")"
    
    case "${1:-once}" in
        "continuous")
            continuous_monitoring
            ;;
        "once")
            run_health_checks
            ;;
        "metrics")
            get_service_metrics
            ;;
        *)
            echo "Usage: $0 [once|continuous|metrics]"
            echo "  once       - Run health checks once (default)"
            echo "  continuous - Run health checks continuously"
            echo "  metrics    - Collect and display metrics only"
            exit 1
            ;;
    esac
}

# Run main function with arguments
main "$@"