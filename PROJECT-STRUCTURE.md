# da Realest Geek Project Structure

## Overview

This document outlines the complete project structure for the da Realest Geek SaaS platform, designed as a monorepo with separate frontend and backend applications optimized for Coolify VPS deployment.

## Root Directory Structure

```
da-realest-geek/
├── 📁 apps/                           # Application workspaces
│   ├── 📁 web/                        # Next.js frontend application
│   └── 📁 api/                        # NestJS backend application
├── 📁 packages/                       # Shared packages
│   ├── 📁 ui/                         # Shared UI components
│   ├── 📁 config/                     # Shared configurations
│   ├── 📁 types/                      # Shared TypeScript types
│   └── 📁 utils/                      # Shared utilities
├── 📁 docs/                           # Documentation
├── 📁 scripts/                        # Build and deployment scripts
├── 📁 docker/                         # Docker configurations
├── 📁 monitoring/                     # Monitoring configurations
├── 📁 security/                       # Security configurations
├── 📄 package.json                    # Root package.json (monorepo)
├── 📄 turbo.json                      # Turbo build configuration
├── 📄 docker-compose.yml              # Docker Compose for local dev
├── 📄 Dockerfile                      # Production Docker image
├── 📄 coolify.yml                     # Coolify deployment config
├── 📄 .env.example                    # Environment variables template
├── 📄 README.md                       # Project documentation
└── 📄 DEPLOYMENT-CHECKLIST.md         # Deployment checklist
```

## Frontend Application (`apps/web/`)

```
apps/web/
├── 📁 src/
│   ├── 📁 app/                        # Next.js 13+ App Router
│   │   ├── 📁 (auth)/                 # Authentication routes
│   │   │   ├── 📁 login/
│   │   │   ├── 📁 register/
│   │   │   └── 📁 forgot-password/
│   │   ├── 📁 (dashboard)/            # Protected dashboard routes
│   │   │   ├── 📁 dashboard/
│   │   │   ├── 📁 leads/
│   │   │   ├── 📁 calendar/
│   │   │   ├── 📁 marketing/
│   │   │   ├── 📁 contacts/
│   │   │   ├── 📁 documents/
│   │   │   ├── 📁 analytics/
│   │   │   └── 📁 settings/
│   │   ├── 📁 api/                    # API routes (Next.js API)
│   │   │   ├── 📁 auth/
│   │   │   ├── 📁 webhooks/
│   │   │   └── 📁 upload/
│   │   ├── 📄 layout.tsx              # Root layout
│   │   ├── 📄 page.tsx                # Landing page
│   │   ├── 📄 loading.tsx             # Global loading UI
│   │   ├── 📄 error.tsx               # Global error UI
│   │   └── 📄 not-found.tsx           # 404 page
│   ├── 📁 components/                 # React components
│   │   ├── 📁 ui/                     # Base UI components
│   │   │   ├── 📄 button.tsx
│   │   │   ├── 📄 input.tsx
│   │   │   ├── 📄 modal.tsx
│   │   │   ├── 📄 table.tsx
│   │   │   └── 📄 form.tsx
│   │   ├── 📁 forms/                  # Form components
│   │   │   ├── 📄 lead-form.tsx
│   │   │   ├── 📄 contact-form.tsx
│   │   │   └── 📄 appointment-form.tsx
│   │   ├── 📁 charts/                 # Chart components
│   │   │   ├── 📄 line-chart.tsx
│   │   │   ├── 📄 bar-chart.tsx
│   │   │   └── 📄 pie-chart.tsx
│   │   ├── 📁 layout/                 # Layout components
│   │   │   ├── 📄 header.tsx
│   │   │   ├── 📄 sidebar.tsx
│   │   │   ├── 📄 footer.tsx
│   │   │   └── 📄 navigation.tsx
│   │   └── 📁 features/               # Feature-specific components
│   │       ├── 📁 leads/
│   │       ├── 📁 calendar/
│   │       ├── 📁 marketing/
│   │       ├── 📁 documents/
│   │       └── 📁 analytics/
│   ├── 📁 lib/                        # Utility libraries
│   │   ├── 📄 auth.ts                 # Authentication utilities
│   │   ├── 📄 api.ts                  # API client
│   │   ├── 📄 utils.ts                # General utilities
│   │   ├── 📄 validations.ts          # Form validations
│   │   └── 📄 constants.ts            # Application constants
│   ├── 📁 hooks/                      # Custom React hooks
│   │   ├── 📄 use-auth.ts
│   │   ├── 📄 use-api.ts
│   │   ├── 📄 use-local-storage.ts
│   │   └── 📄 use-debounce.ts
│   ├── 📁 store/                      # State management
│   │   ├── 📄 index.ts                # Store configuration
│   │   ├── 📄 auth-slice.ts           # Authentication state
│   │   ├── 📄 leads-slice.ts          # Leads state
│   │   └── 📄 ui-slice.ts             # UI state
│   ├── 📁 styles/                     # Styling
│   │   ├── 📄 globals.css             # Global styles
│   │   └── 📄 components.css          # Component styles
│   └── 📁 types/                      # TypeScript types
│       ├── 📄 auth.ts
│       ├── 📄 leads.ts
│       ├── 📄 calendar.ts
│       └── 📄 api.ts
├── 📁 public/                         # Static assets
│   ├── 📁 images/
│   ├── 📁 icons/
│   ├── 📄 favicon.ico
│   └── 📄 manifest.json
├── 📄 package.json                    # Frontend dependencies
├── 📄 next.config.js                  # Next.js configuration
├── 📄 tailwind.config.js              # Tailwind CSS configuration
├── 📄 tsconfig.json                   # TypeScript configuration
└── 📄 .eslintrc.json                  # ESLint configuration
```

## Backend Application (`apps/api/`)

```
apps/api/
├── 📁 src/
│   ├── 📁 modules/                    # Feature modules
│   │   ├── 📁 auth/                   # Authentication module
│   │   │   ├── 📄 auth.controller.ts
│   │   │   ├── 📄 auth.service.ts
│   │   │   ├── 📄 auth.module.ts
│   │   │   ├── 📄 jwt.strategy.ts
│   │   │   └── 📄 auth.guard.ts
│   │   ├── 📁 users/                  # User management
│   │   │   ├── 📄 users.controller.ts
│   │   │   ├── 📄 users.service.ts
│   │   │   ├── 📄 users.module.ts
│   │   │   └── 📄 user.entity.ts
│   │   ├── 📁 leads/                  # Lead management
│   │   │   ├── 📄 leads.controller.ts
│   │   │   ├── 📄 leads.service.ts
│   │   │   ├── 📄 leads.module.ts
│   │   │   └── 📄 lead.entity.ts
│   │   ├── 📁 calendar/               # Calendar & scheduling
│   │   │   ├── 📄 calendar.controller.ts
│   │   │   ├── 📄 calendar.service.ts
│   │   │   ├── 📄 calendar.module.ts
│   │   │   └── 📄 event.entity.ts
│   │   ├── 📁 marketing/              # AI marketing
│   │   │   ├── 📄 marketing.controller.ts
│   │   │   ├── 📄 marketing.service.ts
│   │   │   ├── 📄 marketing.module.ts
│   │   │   └── 📄 campaign.entity.ts
│   │   ├── 📁 documents/              # Document management
│   │   │   ├── 📄 documents.controller.ts
│   │   │   ├── 📄 documents.service.ts
│   │   │   ├── 📄 documents.module.ts
│   │   │   └── 📄 document.entity.ts
│   │   ├── 📁 analytics/              # Analytics & reporting
│   │   │   ├── 📄 analytics.controller.ts
│   │   │   ├── 📄 analytics.service.ts
│   │   │   └── 📄 analytics.module.ts
│   │   └── 📁 notifications/           # Notifications
│   │       ├── 📄 notifications.controller.ts
│   │       ├── 📄 notifications.service.ts
│   │       └── 📄 notifications.module.ts
│   ├── 📁 common/                     # Shared utilities
│   │   ├── 📁 decorators/             # Custom decorators
│   │   ├── 📁 filters/                # Exception filters
│   │   ├── 📁 guards/                 # Route guards
│   │   ├── 📁 interceptors/           # Request interceptors
│   │   ├── 📁 pipes/                  # Validation pipes
│   │   └── 📁 middleware/             # Custom middleware
│   ├── 📁 config/                     # Configuration
│   │   ├── 📄 database.config.ts      # Database configuration
│   │   ├── 📄 redis.config.ts         # Redis configuration
│   │   ├── 📄 jwt.config.ts           # JWT configuration
│   │   └── 📄 app.config.ts           # Application configuration
│   ├── 📁 database/                   # Database related
│   │   ├── 📁 migrations/             # Prisma migrations
│   │   ├── 📁 seeds/                  # Database seeds
│   │   └── 📄 schema.prisma           # Prisma schema
│   ├── 📁 integrations/               # Third-party integrations
│   │   ├── 📁 openai/                 # OpenAI integration
│   │   ├── 📁 google/                 # Google APIs
│   │   ├── 📁 microsoft/              # Microsoft Graph
│   │   ├── 📁 twilio/                 # Twilio SMS/WhatsApp
│   │   ├── 📁 sendgrid/               # SendGrid email
│   │   ├── 📁 stripe/                 # Stripe payments
│   │   └── 📁 aws/                    # AWS S3 storage
│   ├── 📁 jobs/                       # Background jobs
│   │   ├── 📄 email.processor.ts      # Email queue processor
│   │   ├── 📄 ai.processor.ts         # AI processing jobs
│   │   └── 📄 analytics.processor.ts  # Analytics jobs
│   ├── 📄 app.module.ts               # Root application module
│   ├── 📄 app.controller.ts           # Root controller
│   ├── 📄 app.service.ts              # Root service
│   └── 📄 main.ts                     # Application entry point
├── 📁 test/                           # Test files
│   ├── 📁 unit/                       # Unit tests
│   ├── 📁 integration/                # Integration tests
│   └── 📁 e2e/                        # End-to-end tests
├── 📄 package.json                    # Backend dependencies
├── 📄 nest-cli.json                   # NestJS CLI configuration
├── 📄 tsconfig.json                   # TypeScript configuration
├── 📄 tsconfig.build.json             # Build TypeScript config
└── 📄 .eslintrc.js                    # ESLint configuration
```

## Shared Packages (`packages/`)

```
packages/
├── 📁 ui/                             # Shared UI components
│   ├── 📁 src/
│   │   ├── 📁 components/
│   │   ├── 📁 hooks/
│   │   └── 📄 index.ts
│   ├── 📄 package.json
│   └── 📄 tsconfig.json
├── 📁 config/                         # Shared configurations
│   ├── 📁 eslint/
│   ├── 📁 typescript/
│   ├── 📁 tailwind/
│   └── 📄 package.json
├── 📁 types/                          # Shared TypeScript types
│   ├── 📄 api.ts
│   ├── 📄 auth.ts
│   ├── 📄 database.ts
│   └── 📄 package.json
└── 📁 utils/                          # Shared utilities
    ├── 📄 validation.ts
    ├── 📄 formatting.ts
    ├── 📄 constants.ts
    └── 📄 package.json
```

## Documentation (`docs/`)

```
docs/
├── 📄 api-documentation.yml           # OpenAPI specification
├── 📄 architecture.md                 # System architecture
├── 📄 deployment.md                   # Deployment guide
├── 📄 development.md                  # Development setup
├── 📄 features.md                     # Feature documentation
├── 📄 security.md                     # Security guidelines
└── 📁 images/                         # Documentation images
```

## Scripts (`scripts/`)

```
scripts/
├── 📄 deploy-coolify.sh               # Coolify deployment script
├── 📄 backup-restore.sh               # Backup and restore utilities
├── 📄 healthcheck.sh                  # Health check script
├── 📄 setup-dev.sh                    # Development setup
├── 📄 build.sh                        # Build script
└── 📄 test.sh                         # Test runner script
```

## Docker Configuration (`docker/`)

```
docker/
├── 📄 Dockerfile.dev                  # Development Dockerfile
├── 📄 Dockerfile.prod                 # Production Dockerfile
├── 📄 docker-compose.dev.yml          # Development compose
├── 📄 docker-compose.prod.yml         # Production compose
├── 📄 nginx.conf                      # Nginx configuration
├── 📄 supervisord.conf                # Supervisor configuration
└── 📄 docker-entrypoint.sh            # Container entry point
```

## Monitoring (`monitoring/`)

```
monitoring/
├── 📄 prometheus.yml                  # Prometheus configuration
├── 📄 alert_rules.yml                 # Prometheus alert rules
├── 📄 grafana-dashboard.json          # Grafana dashboard
└── 📁 dashboards/                     # Additional dashboards
```

## Security (`security/`)

```
security/
├── 📄 security-config.yml             # Security policies
├── 📄 .securityignore                 # Security scan ignore
└── 📁 policies/                       # Security policies
```

## Key Features by Directory

### Frontend (`apps/web/`)
- **Next.js 13+ App Router**: Modern routing with layouts
- **TypeScript**: Full type safety
- **Tailwind CSS**: Utility-first styling
- **Zustand**: Lightweight state management
- **React Hook Form**: Form handling
- **Zod**: Schema validation
- **Framer Motion**: Animations
- **Recharts**: Data visualization

### Backend (`apps/api/`)
- **NestJS**: Scalable Node.js framework
- **Prisma**: Type-safe database ORM
- **PostgreSQL**: Primary database
- **Redis**: Caching and sessions
- **Bull Queue**: Background job processing
- **Passport**: Authentication strategies
- **Swagger**: API documentation
- **Winston**: Logging

### Deployment
- **Docker**: Containerized deployment
- **Coolify**: VPS deployment platform
- **Nginx**: Reverse proxy and load balancing
- **Supervisor**: Process management
- **GitHub Actions**: CI/CD pipeline
- **Prometheus**: Monitoring and alerting
- **Grafana**: Metrics visualization

## Development Workflow

1. **Local Development**
   ```bash
   npm install
   npm run dev
   ```

2. **Testing**
   ```bash
   npm run test
   npm run test:e2e
   ```

3. **Building**
   ```bash
   npm run build
   ```

4. **Deployment**
   ```bash
   ./scripts/deploy-coolify.sh
   ```

## Environment Configuration

- **Development**: `.env.local`
- **Staging**: `.env.staging`
- **Production**: `.env.production`
- **Example**: `.env.example`

## Database Schema

- **Prisma Schema**: `apps/api/src/database/schema.prisma`
- **Migrations**: `apps/api/src/database/migrations/`
- **Seeds**: `apps/api/src/database/seeds/`

## API Documentation

- **OpenAPI Spec**: `docs/api-documentation.yml`
- **Swagger UI**: Available at `/api/docs` in development
- **Postman Collection**: Generated from OpenAPI spec

## Monitoring and Logging

- **Application Logs**: Structured JSON logging with Winston
- **Access Logs**: Nginx access logs
- **Error Tracking**: Sentry integration
- **Performance Monitoring**: New Relic or DataDog
- **Uptime Monitoring**: Pingdom or UptimeRobot

## Security Considerations

- **Authentication**: JWT with refresh tokens
- **Authorization**: Role-based access control (RBAC)
- **Data Encryption**: At rest and in transit
- **Input Validation**: Zod schemas and NestJS pipes
- **Rate Limiting**: Express rate limit
- **CORS**: Configured for specific origins
- **Security Headers**: Helmet.js

## Scalability Features

- **Horizontal Scaling**: Stateless application design
- **Database Scaling**: Read replicas and connection pooling
- **Caching**: Redis for session and data caching
- **CDN**: Static asset delivery
- **Load Balancing**: Nginx upstream configuration
- **Queue Processing**: Background job processing

This structure provides a solid foundation for a scalable, maintainable SaaS platform optimized for Coolify VPS deployment.