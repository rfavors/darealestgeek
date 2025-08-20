#!/bin/bash

# Backup and Restore Script for daRealestGeek
# This script handles database backups, file backups, and restoration procedures

set -e

# Configuration
BACKUP_DIR=${BACKUP_DIR:-"/var/backups/darealestgeek"}
S3_BUCKET=${S3_BUCKET:-"darealestgeek-backups"}
RETENTION_DAYS=${RETENTION_DAYS:-30}
COMPRESSION_LEVEL=${COMPRESSION_LEVEL:-6}
ENCRYPTION_KEY_FILE=${ENCRYPTION_KEY_FILE:-"/etc/darealestgeek/backup.key"}

# Database configuration
DB_HOST=${DB_HOST:-"postgres"}
DB_PORT=${DB_PORT:-5432}
DB_NAME=${DB_NAME:-"darealestgeek"}
DB_USER=${DB_USER:-"postgres"}
PGPASSWORD=${DB_PASSWORD}

# Redis configuration
REDIS_HOST=${REDIS_HOST:-"redis"}
REDIS_PORT=${REDIS_PORT:-6379}
REDIS_PASSWORD=${REDIS_PASSWORD}

# File paths to backup
FILE_PATHS=(
    "/app/uploads"
    "/app/storage"
    "/app/logs"
    "/etc/nginx/ssl"
    "/app/.env"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') ${RED}[ERROR]${NC} $1"
}

# Utility functions
check_dependencies() {
    local deps=("pg_dump" "pg_restore" "redis-cli" "aws" "gpg" "tar" "gzip")
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            log_error "Required dependency '$dep' is not installed"
            exit 1
        fi
    done
    
    log_success "All dependencies are available"
}

setup_backup_directory() {
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    BACKUP_TIMESTAMP="$timestamp"
    CURRENT_BACKUP_DIR="$BACKUP_DIR/$timestamp"
    
    mkdir -p "$CURRENT_BACKUP_DIR"
    log_info "Created backup directory: $CURRENT_BACKUP_DIR"
}

generate_encryption_key() {
    if [[ ! -f "$ENCRYPTION_KEY_FILE" ]]; then
        log_info "Generating new encryption key..."
        mkdir -p "$(dirname "$ENCRYPTION_KEY_FILE")"
        openssl rand -base64 32 > "$ENCRYPTION_KEY_FILE"
        chmod 600 "$ENCRYPTION_KEY_FILE"
        log_success "Encryption key generated: $ENCRYPTION_KEY_FILE"
    fi
}

# Database backup functions
backup_postgresql() {
    log_info "Starting PostgreSQL backup..."
    
    local backup_file="$CURRENT_BACKUP_DIR/postgresql_${BACKUP_TIMESTAMP}.sql"
    local compressed_file="${backup_file}.gz"
    local encrypted_file="${compressed_file}.gpg"
    
    # Create database dump
    if PGPASSWORD="$PGPASSWORD" pg_dump \
        -h "$DB_HOST" \
        -p "$DB_PORT" \
        -U "$DB_USER" \
        -d "$DB_NAME" \
        --verbose \
        --no-password \
        --format=custom \
        --compress="$COMPRESSION_LEVEL" \
        --file="$backup_file"; then
        
        log_success "PostgreSQL dump created: $backup_file"
        
        # Compress the backup
        gzip -"$COMPRESSION_LEVEL" "$backup_file"
        log_success "PostgreSQL backup compressed: $compressed_file"
        
        # Encrypt the backup
        if [[ -f "$ENCRYPTION_KEY_FILE" ]]; then
            gpg --batch --yes --cipher-algo AES256 \
                --compress-algo 2 \
                --symmetric \
                --passphrase-file "$ENCRYPTION_KEY_FILE" \
                --output "$encrypted_file" \
                "$compressed_file"
            
            rm "$compressed_file"
            log_success "PostgreSQL backup encrypted: $encrypted_file"
        fi
        
        # Generate checksum
        sha256sum "$encrypted_file" > "${encrypted_file}.sha256"
        log_success "PostgreSQL backup checksum generated"
        
    else
        log_error "Failed to create PostgreSQL backup"
        return 1
    fi
}

backup_redis() {
    log_info "Starting Redis backup..."
    
    local backup_file="$CURRENT_BACKUP_DIR/redis_${BACKUP_TIMESTAMP}.rdb"
    local compressed_file="${backup_file}.gz"
    local encrypted_file="${compressed_file}.gpg"
    
    # Trigger Redis save
    if [[ -n "$REDIS_PASSWORD" ]]; then
        redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -a "$REDIS_PASSWORD" BGSAVE
    else
        redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" BGSAVE
    fi
    
    # Wait for save to complete
    local save_in_progress=1
    while [[ $save_in_progress -eq 1 ]]; do
        sleep 2
        if [[ -n "$REDIS_PASSWORD" ]]; then
            save_in_progress=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -a "$REDIS_PASSWORD" LASTSAVE)
        else
            save_in_progress=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" LASTSAVE)
        fi
    done
    
    # Copy Redis dump file
    if docker cp redis:/data/dump.rdb "$backup_file"; then
        log_success "Redis dump copied: $backup_file"
        
        # Compress and encrypt
        gzip -"$COMPRESSION_LEVEL" "$backup_file"
        
        if [[ -f "$ENCRYPTION_KEY_FILE" ]]; then
            gpg --batch --yes --cipher-algo AES256 \
                --compress-algo 2 \
                --symmetric \
                --passphrase-file "$ENCRYPTION_KEY_FILE" \
                --output "$encrypted_file" \
                "$compressed_file"
            
            rm "$compressed_file"
            log_success "Redis backup encrypted: $encrypted_file"
        fi
        
        # Generate checksum
        sha256sum "$encrypted_file" > "${encrypted_file}.sha256"
        log_success "Redis backup checksum generated"
        
    else
        log_error "Failed to copy Redis dump file"
        return 1
    fi
}

# File backup functions
backup_files() {
    log_info "Starting file backup..."
    
    local backup_file="$CURRENT_BACKUP_DIR/files_${BACKUP_TIMESTAMP}.tar"
    local compressed_file="${backup_file}.gz"
    local encrypted_file="${compressed_file}.gpg"
    
    # Create tar archive of all specified paths
    local tar_args=()
    for path in "${FILE_PATHS[@]}"; do
        if [[ -e "$path" ]]; then
            tar_args+=("$path")
        else
            log_warning "Path does not exist, skipping: $path"
        fi
    done
    
    if [[ ${#tar_args[@]} -gt 0 ]]; then
        if tar -cf "$backup_file" "${tar_args[@]}"; then
            log_success "File archive created: $backup_file"
            
            # Compress and encrypt
            gzip -"$COMPRESSION_LEVEL" "$backup_file"
            
            if [[ -f "$ENCRYPTION_KEY_FILE" ]]; then
                gpg --batch --yes --cipher-algo AES256 \
                    --compress-algo 2 \
                    --symmetric \
                    --passphrase-file "$ENCRYPTION_KEY_FILE" \
                    --output "$encrypted_file" \
                    "$compressed_file"
                
                rm "$compressed_file"
                log_success "File backup encrypted: $encrypted_file"
            fi
            
            # Generate checksum
            sha256sum "$encrypted_file" > "${encrypted_file}.sha256"
            log_success "File backup checksum generated"
            
        else
            log_error "Failed to create file archive"
            return 1
        fi
    else
        log_warning "No valid file paths found for backup"
    fi
}

# Backup metadata
create_backup_metadata() {
    log_info "Creating backup metadata..."
    
    local metadata_file="$CURRENT_BACKUP_DIR/metadata.json"
    
    cat > "$metadata_file" << EOF
{
  "timestamp": "$BACKUP_TIMESTAMP",
  "date": "$(date -Iseconds)",
  "version": "$(cat /app/package.json | jq -r '.version' 2>/dev/null || echo 'unknown')",
  "environment": "${ENVIRONMENT:-production}",
  "database": {
    "host": "$DB_HOST",
    "port": "$DB_PORT",
    "name": "$DB_NAME",
    "user": "$DB_USER"
  },
  "redis": {
    "host": "$REDIS_HOST",
    "port": "$REDIS_PORT"
  },
  "files": $(printf '%s\n' "${FILE_PATHS[@]}" | jq -R . | jq -s .),
  "backup_size": "$(du -sh "$CURRENT_BACKUP_DIR" | cut -f1)",
  "checksum": "$(find "$CURRENT_BACKUP_DIR" -name "*.sha256" -exec cat {} \; | sha256sum | cut -d' ' -f1)"
}
EOF
    
    log_success "Backup metadata created: $metadata_file"
}

# Cloud upload functions
upload_to_s3() {
    if [[ -z "$S3_BUCKET" ]]; then
        log_warning "S3_BUCKET not configured, skipping cloud upload"
        return 0
    fi
    
    log_info "Uploading backup to S3..."
    
    local s3_path="s3://$S3_BUCKET/backups/$BACKUP_TIMESTAMP/"
    
    if aws s3 sync "$CURRENT_BACKUP_DIR" "$s3_path" --delete; then
        log_success "Backup uploaded to S3: $s3_path"
        
        # Set lifecycle policy for automatic cleanup
        aws s3api put-object-lifecycle-configuration \
            --bucket "$S3_BUCKET" \
            --lifecycle-configuration file:///dev/stdin << EOF
{
  "Rules": [
    {
      "ID": "DeleteOldBackups",
      "Status": "Enabled",
      "Filter": {
        "Prefix": "backups/"
      },
      "Expiration": {
        "Days": $RETENTION_DAYS
      }
    }
  ]
}
EOF
        
        log_success "S3 lifecycle policy configured for $RETENTION_DAYS days retention"
    else
        log_error "Failed to upload backup to S3"
        return 1
    fi
}

# Cleanup functions
cleanup_old_backups() {
    log_info "Cleaning up old local backups..."
    
    find "$BACKUP_DIR" -type d -name "*_*" -mtime +"$RETENTION_DAYS" -exec rm -rf {} + 2>/dev/null || true
    
    log_success "Old local backups cleaned up (older than $RETENTION_DAYS days)"
}

# Restoration functions
list_backups() {
    log_info "Available backups:"
    
    echo "Local backups:"
    find "$BACKUP_DIR" -type d -name "*_*" | sort -r | head -10
    
    if [[ -n "$S3_BUCKET" ]]; then
        echo "\nS3 backups:"
        aws s3 ls "s3://$S3_BUCKET/backups/" | tail -10
    fi
}

restore_from_backup() {
    local backup_path="$1"
    
    if [[ -z "$backup_path" ]]; then
        log_error "Backup path is required"
        return 1
    fi
    
    log_info "Starting restoration from: $backup_path"
    
    # Download from S3 if needed
    if [[ "$backup_path" == s3://* ]]; then
        local local_restore_dir="$BACKUP_DIR/restore_$(date '+%Y%m%d_%H%M%S')"
        mkdir -p "$local_restore_dir"
        
        if aws s3 sync "$backup_path" "$local_restore_dir"; then
            backup_path="$local_restore_dir"
            log_success "Backup downloaded from S3"
        else
            log_error "Failed to download backup from S3"
            return 1
        fi
    fi
    
    # Verify backup integrity
    if ! verify_backup_integrity "$backup_path"; then
        log_error "Backup integrity verification failed"
        return 1
    fi
    
    # Restore database
    restore_postgresql "$backup_path"
    
    # Restore Redis
    restore_redis "$backup_path"
    
    # Restore files
    restore_files "$backup_path"
    
    log_success "Restoration completed successfully"
}

verify_backup_integrity() {
    local backup_path="$1"
    
    log_info "Verifying backup integrity..."
    
    # Check if all expected files exist
    local required_files=("metadata.json")
    
    for file in "${required_files[@]}"; do
        if [[ ! -f "$backup_path/$file" ]]; then
            log_error "Required file missing: $file"
            return 1
        fi
    done
    
    # Verify checksums
    local checksum_files=("$backup_path"/*.sha256)
    for checksum_file in "${checksum_files[@]}"; do
        if [[ -f "$checksum_file" ]]; then
            local dir=$(dirname "$checksum_file")
            if ! (cd "$dir" && sha256sum -c "$(basename "$checksum_file")"); then
                log_error "Checksum verification failed for: $checksum_file"
                return 1
            fi
        fi
    done
    
    log_success "Backup integrity verified"
    return 0
}

restore_postgresql() {
    local backup_path="$1"
    local encrypted_file=$(find "$backup_path" -name "postgresql_*.sql.gz.gpg" | head -1)
    
    if [[ -z "$encrypted_file" ]]; then
        log_warning "No PostgreSQL backup found"
        return 0
    fi
    
    log_info "Restoring PostgreSQL from: $encrypted_file"
    
    local temp_dir=$(mktemp -d)
    local decrypted_file="$temp_dir/postgresql.sql.gz"
    local sql_file="$temp_dir/postgresql.sql"
    
    # Decrypt and decompress
    gpg --batch --yes --decrypt \
        --passphrase-file "$ENCRYPTION_KEY_FILE" \
        --output "$decrypted_file" \
        "$encrypted_file"
    
    gunzip "$decrypted_file"
    
    # Restore database
    if PGPASSWORD="$PGPASSWORD" pg_restore \
        -h "$DB_HOST" \
        -p "$DB_PORT" \
        -U "$DB_USER" \
        -d "$DB_NAME" \
        --verbose \
        --clean \
        --if-exists \
        "$sql_file"; then
        
        log_success "PostgreSQL restored successfully"
    else
        log_error "Failed to restore PostgreSQL"
    fi
    
    # Cleanup
    rm -rf "$temp_dir"
}

restore_redis() {
    local backup_path="$1"
    local encrypted_file=$(find "$backup_path" -name "redis_*.rdb.gz.gpg" | head -1)
    
    if [[ -z "$encrypted_file" ]]; then
        log_warning "No Redis backup found"
        return 0
    fi
    
    log_info "Restoring Redis from: $encrypted_file"
    
    local temp_dir=$(mktemp -d)
    local decrypted_file="$temp_dir/redis.rdb.gz"
    local rdb_file="$temp_dir/dump.rdb"
    
    # Decrypt and decompress
    gpg --batch --yes --decrypt \
        --passphrase-file "$ENCRYPTION_KEY_FILE" \
        --output "$decrypted_file" \
        "$encrypted_file"
    
    gunzip "$decrypted_file"
    mv "$temp_dir/redis.rdb" "$rdb_file"
    
    # Stop Redis, replace dump file, start Redis
    docker stop redis
    docker cp "$rdb_file" redis:/data/dump.rdb
    docker start redis
    
    log_success "Redis restored successfully"
    
    # Cleanup
    rm -rf "$temp_dir"
}

restore_files() {
    local backup_path="$1"
    local encrypted_file=$(find "$backup_path" -name "files_*.tar.gz.gpg" | head -1)
    
    if [[ -z "$encrypted_file" ]]; then
        log_warning "No file backup found"
        return 0
    fi
    
    log_info "Restoring files from: $encrypted_file"
    
    local temp_dir=$(mktemp -d)
    local decrypted_file="$temp_dir/files.tar.gz"
    
    # Decrypt and decompress
    gpg --batch --yes --decrypt \
        --passphrase-file "$ENCRYPTION_KEY_FILE" \
        --output "$decrypted_file" \
        "$encrypted_file"
    
    # Extract files
    if tar -xzf "$decrypted_file" -C /; then
        log_success "Files restored successfully"
    else
        log_error "Failed to restore files"
    fi
    
    # Cleanup
    rm -rf "$temp_dir"
}

# Main functions
run_backup() {
    log_info "Starting backup process..."
    
    check_dependencies
    generate_encryption_key
    setup_backup_directory
    
    # Perform backups
    backup_postgresql
    backup_redis
    backup_files
    create_backup_metadata
    
    # Upload to cloud
    upload_to_s3
    
    # Cleanup old backups
    cleanup_old_backups
    
    log_success "Backup process completed successfully"
    log_info "Backup location: $CURRENT_BACKUP_DIR"
}

# Main script logic
main() {
    case "${1:-backup}" in
        "backup")
            run_backup
            ;;
        "restore")
            restore_from_backup "$2"
            ;;
        "list")
            list_backups
            ;;
        "verify")
            verify_backup_integrity "$2"
            ;;
        *)
            echo "Usage: $0 [backup|restore|list|verify] [backup_path]"
            echo "  backup           - Create a new backup (default)"
            echo "  restore <path>   - Restore from backup path"
            echo "  list             - List available backups"
            echo "  verify <path>    - Verify backup integrity"
            exit 1
            ;;
    esac
}

# Run main function with arguments
main "$@"