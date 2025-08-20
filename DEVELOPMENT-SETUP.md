# daRealestGeek Development Setup Guide

## Prerequisites

Before setting up the development environment, ensure you have the following installed:

### Required Software
- **Node.js** (v18.17.0 or higher)
- **npm** (v9.0.0 or higher) or **pnpm** (v8.0.0 or higher)
- **Docker** (v20.10.0 or higher)
- **Docker Compose** (v2.0.0 or higher)
- **Git** (v2.30.0 or higher)
- **PostgreSQL** (v14.0 or higher) - for local development
- **Redis** (v6.0 or higher) - for local development

### Recommended Tools
- **Visual Studio Code** with extensions:
  - TypeScript and JavaScript Language Features
  - Prisma
  - Tailwind CSS IntelliSense
  - ESLint
  - Prettier
  - Docker
  - GitLens
- **Postman** or **Insomnia** for API testing
- **TablePlus** or **pgAdmin** for database management
- **Redis Commander** for Redis management

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/darealestgeek.git
cd darealestgeek
```

### 2. Install Dependencies

```bash
# Install all dependencies for the monorepo
npm install

# Or using pnpm (recommended for better performance)
pnpm install
```

### 3. Environment Setup

```bash
# Copy environment template
cp .env.example .env.local

# Edit the environment file with your local settings
# You'll need to add API keys and configure database connections
```

### 4. Database Setup

#### Option A: Using Docker (Recommended)

```bash
# Start PostgreSQL and Redis using Docker Compose
docker-compose up -d postgres redis

# Wait for services to be ready
docker-compose logs -f postgres redis
```

#### Option B: Local Installation

```bash
# Install PostgreSQL and Redis locally
# macOS with Homebrew
brew install postgresql redis
brew services start postgresql
brew services start redis

# Ubuntu/Debian
sudo apt-get install postgresql postgresql-contrib redis-server
sudo systemctl start postgresql
sudo systemctl start redis-server

# Windows
# Download and install from official websites
```

### 5. Database Migration and Seeding

```bash
# Generate Prisma client
npm run db:generate

# Run database migrations
npm run db:migrate

# Seed the database with initial data
npm run db:seed
```

### 6. Start Development Servers

```bash
# Start all services in development mode
npm run dev

# Or start services individually
npm run dev:web    # Frontend only (port 3000)
npm run dev:api    # Backend only (port 3001)
```

### 7. Verify Setup

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:3001
- **API Documentation**: http://localhost:3001/api/docs
- **Database**: localhost:5432 (postgres/postgres)
- **Redis**: localhost:6379

## Detailed Setup Instructions

### Environment Variables

Create a `.env.local` file in the root directory with the following variables:

```bash
# Database
DATABASE_URL="postgresql://postgres:postgres@localhost:5432/darealestgeek_dev"
DATABASE_HOST="localhost"
DATABASE_PORT="5432"
DATABASE_USERNAME="postgres"
DATABASE_PASSWORD="postgres"
DATABASE_NAME="darealestgeek_dev"

# Redis
REDIS_URL="redis://localhost:6379"
REDIS_HOST="localhost"
REDIS_PORT="6379"
REDIS_PASSWORD=""

# Application URLs
NEXTAUTH_URL="http://localhost:3000"
NEXTAUTH_SECRET="your-nextauth-secret-key-here"
API_URL="http://localhost:3001"
WEB_URL="http://localhost:3000"

# JWT Configuration
JWT_SECRET="your-jwt-secret-key-here"
JWT_EXPIRES_IN="7d"
JWT_REFRESH_SECRET="your-jwt-refresh-secret-here"
JWT_REFRESH_EXPIRES_IN="30d"

# OpenAI (for AI features)
OPENAI_API_KEY="sk-your-openai-api-key"
OPENAI_MODEL="gpt-4"

# Google OAuth (optional for development)
GOOGLE_CLIENT_ID="your-google-client-id"
GOOGLE_CLIENT_SECRET="your-google-client-secret"

# Microsoft Graph (optional for development)
MICROSOFT_CLIENT_ID="your-microsoft-client-id"
MICROSOFT_CLIENT_SECRET="your-microsoft-client-secret"

# Twilio (optional for development)
TWILIO_ACCOUNT_SID="your-twilio-account-sid"
TWILIO_AUTH_TOKEN="your-twilio-auth-token"
TWILIO_PHONE_NUMBER="+1234567890"

# SendGrid (optional for development)
SENDGRID_API_KEY="your-sendgrid-api-key"
SENDGRID_FROM_EMAIL="noreply@darealestgeek.com"

# Stripe (optional for development)
STRIPE_PUBLIC_KEY="pk_test_your-stripe-public-key"
STRIPE_SECRET_KEY="sk_test_your-stripe-secret-key"
STRIPE_WEBHOOK_SECRET="whsec_your-stripe-webhook-secret"

# AWS S3 (optional for development)
AWS_ACCESS_KEY_ID="your-aws-access-key"
AWS_SECRET_ACCESS_KEY="your-aws-secret-key"
AWS_REGION="us-east-1"
AWS_S3_BUCKET="darealestgeek-dev"

# Development Settings
NODE_ENV="development"
LOG_LEVEL="debug"
ENABLE_SWAGGER="true"
ENABLE_CORS="true"
```

### Database Configuration

#### PostgreSQL Setup

1. **Create Database**:
   ```sql
   CREATE DATABASE darealestgeek_dev;
   CREATE USER darealestgeek WITH PASSWORD 'password';
   GRANT ALL PRIVILEGES ON DATABASE darealestgeek_dev TO darealestgeek;
   ```

2. **Configure Connection**:
   Update the `DATABASE_URL` in your `.env.local` file.

3. **Run Migrations**:
   ```bash
   cd apps/api
   npx prisma migrate dev
   ```

#### Redis Setup

1. **Start Redis**:
   ```bash
   redis-server
   ```

2. **Test Connection**:
   ```bash
   redis-cli ping
   # Should return: PONG
   ```

### API Keys Setup

For full functionality, you'll need to obtain API keys from various services:

#### OpenAI (Required for AI features)
1. Visit https://platform.openai.com/api-keys
2. Create a new API key
3. Add to `OPENAI_API_KEY` in your environment file

#### Google APIs (Optional)
1. Go to Google Cloud Console
2. Create a new project or select existing
3. Enable Google Calendar API, Gmail API, Google Drive API
4. Create OAuth 2.0 credentials
5. Add client ID and secret to environment file

#### Microsoft Graph (Optional)
1. Go to Azure Portal
2. Register a new application
3. Configure API permissions for Calendar, Mail, OneDrive
4. Add client ID and secret to environment file

#### Other Services
- **Twilio**: https://console.twilio.com/
- **SendGrid**: https://app.sendgrid.com/
- **Stripe**: https://dashboard.stripe.com/
- **AWS**: https://aws.amazon.com/console/

## Development Workflow

### Code Structure

```bash
# Frontend development
cd apps/web
npm run dev          # Start Next.js dev server
npm run build        # Build for production
npm run lint         # Run ESLint
npm run type-check   # TypeScript type checking

# Backend development
cd apps/api
npm run dev          # Start NestJS dev server
npm run build        # Build for production
npm run test         # Run unit tests
npm run test:e2e     # Run e2e tests
```

### Database Operations

```bash
# Prisma operations
npm run db:generate  # Generate Prisma client
npm run db:migrate   # Run migrations
npm run db:reset     # Reset database
npm run db:seed      # Seed database
npm run db:studio    # Open Prisma Studio

# Create new migration
cd apps/api
npx prisma migrate dev --name your_migration_name
```

### Testing

```bash
# Run all tests
npm run test

# Run tests for specific workspace
npm run test:web     # Frontend tests
npm run test:api     # Backend tests

# Run tests in watch mode
npm run test:watch

# Run e2e tests
npm run test:e2e

# Generate test coverage
npm run test:coverage
```

### Code Quality

```bash
# Linting
npm run lint         # Lint all workspaces
npm run lint:fix     # Fix linting issues

# Type checking
npm run type-check   # Check TypeScript types

# Formatting
npm run format       # Format code with Prettier
```

## Debugging

### Frontend Debugging

1. **Browser DevTools**: Use React Developer Tools extension
2. **VS Code Debugging**: Configure launch.json for Next.js
3. **Network Tab**: Monitor API calls and responses
4. **Console Logging**: Use `console.log` for quick debugging

### Backend Debugging

1. **VS Code Debugging**: 
   ```json
   {
     "type": "node",
     "request": "launch",
     "name": "Debug NestJS",
     "program": "${workspaceFolder}/apps/api/src/main.ts",
     "outFiles": ["${workspaceFolder}/apps/api/dist/**/*.js"],
     "runtimeArgs": ["-r", "ts-node/register"]
   }
   ```

2. **Logging**: Use Winston logger for structured logging
3. **Database Queries**: Enable Prisma query logging
4. **API Testing**: Use Postman or Insomnia

### Common Issues and Solutions

#### Port Already in Use
```bash
# Find process using port
lsof -i :3000
# Kill process
kill -9 <PID>
```

#### Database Connection Issues
```bash
# Check PostgreSQL status
pg_isready -h localhost -p 5432

# Reset database connection
npm run db:reset
```

#### Node Modules Issues
```bash
# Clear node_modules and reinstall
rm -rf node_modules package-lock.json
npm install
```

#### Prisma Issues
```bash
# Regenerate Prisma client
npx prisma generate

# Reset Prisma
npx prisma migrate reset
```

## Performance Optimization

### Frontend
- Use Next.js Image component for optimized images
- Implement code splitting with dynamic imports
- Use React.memo for expensive components
- Optimize bundle size with webpack-bundle-analyzer

### Backend
- Use database indexes for frequently queried fields
- Implement caching with Redis
- Use connection pooling for database connections
- Optimize API responses with pagination

## Security Best Practices

### Development Security
- Never commit API keys or secrets
- Use environment variables for sensitive data
- Validate all inputs on both client and server
- Implement proper error handling
- Use HTTPS in production

### Code Security
- Regular dependency updates
- Use ESLint security rules
- Implement proper authentication and authorization
- Sanitize user inputs
- Use parameterized queries

## Deployment

### Local Production Build

```bash
# Build all applications
npm run build

# Start production servers
npm run start
```

### Docker Development

```bash
# Build development image
docker-compose -f docker-compose.dev.yml build

# Start development environment
docker-compose -f docker-compose.dev.yml up
```

## Troubleshooting

### Common Development Issues

1. **Module Not Found Errors**
   - Clear node_modules and reinstall
   - Check import paths
   - Verify package.json dependencies

2. **TypeScript Errors**
   - Run type checking: `npm run type-check`
   - Update type definitions
   - Check tsconfig.json configuration

3. **Database Connection Errors**
   - Verify database is running
   - Check connection string
   - Ensure database exists

4. **API Errors**
   - Check server logs
   - Verify environment variables
   - Test endpoints with Postman

5. **Build Errors**
   - Clear build cache
   - Check for syntax errors
   - Verify all dependencies are installed

### Getting Help

- **Documentation**: Check the `/docs` folder
- **Issues**: Create GitHub issues for bugs
- **Discussions**: Use GitHub Discussions for questions
- **Team Chat**: Use Slack/Discord for real-time help

## Contributing

### Development Guidelines

1. **Branch Naming**: `feature/description`, `bugfix/description`, `hotfix/description`
2. **Commit Messages**: Use conventional commits format
3. **Pull Requests**: Include description, tests, and documentation
4. **Code Review**: All changes require review before merging

### Code Standards

- Follow ESLint and Prettier configurations
- Write unit tests for new features
- Update documentation for API changes
- Use TypeScript for type safety
- Follow component and module naming conventions

---

**Happy coding! 🚀**

For additional help, refer to the project documentation or reach out to the development team.