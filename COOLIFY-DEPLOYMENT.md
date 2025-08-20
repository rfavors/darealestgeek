# Coolify VPS Deployment Guide for daRealestGeek

This guide provides step-by-step instructions for deploying daRealestGeek on a Coolify VPS.

## Prerequisites

- Coolify instance running on your VPS
- Domain name pointed to your VPS IP
- Required API keys (see below)
- At least 4GB RAM and 2 CPU cores recommended

## Required API Keys

Before deployment, ensure you have the following API keys:

### Essential (Required for basic functionality)
- **OpenAI API Key** - For AI features
- **Google Maps API Key** - For location services
- **Stripe API Keys** - For payments (publishable & secret)
- **Auth0 Credentials** - For authentication (domain, client ID, secret)
- **SendGrid API Key** - For email delivery
- **Twilio Credentials** - For SMS/voice (Account SID, Auth Token)

### Optional (Enhanced functionality)
- **Microsoft Graph API** - For Outlook calendar integration
- **Firebase Credentials** - For push notifications
- **AWS S3 Credentials** - For file storage
- **Replicate API Token** - For advanced image processing
- **PostHog API Key** - For analytics

## Deployment Steps

### 1. Prepare Your Coolify Instance

1. **Access Coolify Dashboard**
   ```
   https://your-vps-ip:8000
   ```

2. **Create New Project**
   - Click "New Project"
   - Name: `darealestgeek`
   - Description: `AI-Powered Real Estate SaaS`

### 2. Configure Git Repository

1. **Add Git Source**
   - Repository URL: `https://github.com/yourusername/darealestgeek.git`
   - Branch: `main`
   - Build Pack: `Docker Compose`

2. **Set Build Configuration**
   - Docker Compose File: `docker-compose.yml`
   - Build Command: `./deploy-coolify.sh`

### 3. Environment Variables Setup

In Coolify, navigate to your project's Environment tab and add these variables:

#### Database & Cache
```env
DATABASE_NAME=darealestgeek
DATABASE_USER=postgres
DATABASE_PASSWORD=your_secure_db_password
REDIS_PASSWORD=your_secure_redis_password
```

#### Application URLs
```env
DOMAIN_NAME=yourdomain.com
NEXT_PUBLIC_APP_URL=https://yourdomain.com
NEXT_PUBLIC_API_URL=https://yourdomain.com/api
```

#### Security
```env
JWT_SECRET=your_super_secure_jwt_secret_key_here
NEXTAUTH_SECRET=your_nextauth_secret_here
NEXTAUTH_URL=https://yourdomain.com
```

#### AI Services
```env
OPENAI_API_KEY=sk-your_openai_api_key_here
REPLICATE_API_TOKEN=r8_your_replicate_api_token
```

#### Google Services
```env
GOOGLE_MAPS_API_KEY=your_google_maps_api_key
GOOGLE_CLIENT_ID=your_google_oauth_client_id
GOOGLE_CLIENT_SECRET=your_google_oauth_client_secret
```

#### Communication
```env
TWILIO_ACCOUNT_SID=your_twilio_account_sid
TWILIO_AUTH_TOKEN=your_twilio_auth_token
TWILIO_PHONE_NUMBER=+1234567890
SENDGRID_API_KEY=SG.your_sendgrid_api_key
SENDGRID_FROM_EMAIL=noreply@yourdomain.com
```

#### Payments
```env
STRIPE_SECRET_KEY=sk_live_your_stripe_secret_key
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_your_stripe_publishable_key
STRIPE_WEBHOOK_SECRET=whsec_your_stripe_webhook_secret
```

#### Authentication
```env
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_CLIENT_ID=your_auth0_client_id
AUTH0_CLIENT_SECRET=your_auth0_client_secret
AUTH0_AUDIENCE=https://api.yourdomain.com
```

#### File Storage
```env
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_S3_BUCKET=darealestgeek-files
AWS_REGION=us-east-1
```

### 4. Domain Configuration

1. **Add Domain in Coolify**
   - Go to Domains tab
   - Add your domain: `yourdomain.com`
   - Enable SSL (Let's Encrypt)

2. **DNS Configuration**
   ```
   A Record: yourdomain.com → your_vps_ip
   CNAME: www.yourdomain.com → yourdomain.com
   ```

### 5. Deploy the Application

1. **Trigger Deployment**
   - Click "Deploy" in Coolify
   - Monitor logs for any issues

2. **Verify Services**
   - Check all containers are running
   - Verify health checks pass

### 6. Post-Deployment Configuration

#### Database Setup
1. **Run Migrations**
   ```bash
   # Access the API container
   docker exec -it drg-api npm run db:migrate:deploy
   ```

2. **Seed Initial Data**
   ```bash
   docker exec -it drg-api npm run db:seed
   ```

#### SSL Certificate
- Coolify automatically handles SSL with Let's Encrypt
- Verify HTTPS is working: `https://yourdomain.com`

#### Webhook Configuration
1. **Stripe Webhooks**
   - Endpoint: `https://yourdomain.com/api/webhooks/stripe`
   - Events: `payment_intent.succeeded`, `customer.subscription.updated`

2. **Third-party Webhooks**
   - Zillow: `https://yourdomain.com/api/webhooks/zillow`
   - Facebook: `https://yourdomain.com/api/webhooks/facebook`

## Monitoring & Maintenance

### Health Checks
Coolify automatically monitors:
- Application health endpoints
- Container resource usage
- SSL certificate expiration

### Backup Strategy
1. **Database Backups**
   - Automatic daily backups at 2 AM
   - 7-day retention policy
   - Manual backup: `docker exec drg-postgres pg_dump -U postgres darealestgeek > backup.sql`

2. **File Backups**
   - S3 bucket versioning enabled
   - Cross-region replication recommended

### Scaling

#### Vertical Scaling
- Increase VPS resources in your hosting provider
- Restart services: `docker-compose restart`

#### Horizontal Scaling
- Modify `coolify.yml` replica counts
- Add load balancer for multiple instances

### Updates

1. **Application Updates**
   ```bash
   git pull origin main
   docker-compose build --no-cache
   docker-compose up -d
   ```

2. **Database Migrations**
   ```bash
   docker exec -it drg-api npm run db:migrate:deploy
   ```

## Troubleshooting

### Common Issues

1. **Services Not Starting**
   ```bash
   # Check logs
   docker-compose logs -f
   
   # Check service status
   docker-compose ps
   ```

2. **Database Connection Issues**
   ```bash
   # Test database connection
   docker exec -it drg-postgres psql -U postgres -d darealestgeek
   ```

3. **SSL Certificate Issues**
   - Verify domain DNS is pointing to VPS
   - Check Coolify SSL settings
   - Restart nginx: `docker-compose restart nginx`

4. **High Memory Usage**
   ```bash
   # Monitor resource usage
   docker stats
   
   # Restart services
   docker-compose restart
   ```

### Log Locations
- Application logs: `docker-compose logs [service_name]`
- Nginx logs: `docker exec drg-nginx tail -f /var/log/nginx/access.log`
- Database logs: `docker-compose logs postgres`

### Performance Optimization

1. **Database Optimization**
   ```sql
   -- Add indexes for frequently queried fields
   CREATE INDEX idx_leads_created_at ON leads(created_at);
   CREATE INDEX idx_leads_organization_id ON leads(organization_id);
   ```

2. **Redis Configuration**
   - Increase memory limit if needed
   - Configure appropriate eviction policy

3. **Nginx Optimization**
   - Enable gzip compression (already configured)
   - Implement caching for static assets
   - Configure rate limiting

## Security Considerations

1. **Environment Variables**
   - Never commit secrets to git
   - Use Coolify's secret management
   - Rotate secrets regularly

2. **Network Security**
   - Configure firewall rules
   - Use VPN for administrative access
   - Enable fail2ban for SSH protection

3. **Application Security**
   - Keep dependencies updated
   - Monitor for security vulnerabilities
   - Implement proper CORS policies

## Support

For deployment issues:
1. Check Coolify documentation
2. Review application logs
3. Contact support at support@darealestgeek.com

## Useful Commands

```bash
# View all services
docker-compose ps

# View logs
docker-compose logs -f [service_name]

# Restart specific service
docker-compose restart [service_name]

# Update and restart all services
docker-compose pull && docker-compose up -d

# Database backup
docker exec drg-postgres pg_dump -U postgres darealestgeek > backup_$(date +%Y%m%d).sql

# Database restore
docker exec -i drg-postgres psql -U postgres darealestgeek < backup.sql

# Clear Redis cache
docker exec drg-redis redis-cli FLUSHALL

# Monitor resource usage
docker stats
```