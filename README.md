# da Realest Geek - AI-Powered Real Estate SaaS

**Tagline:** "Where Real Estate Meets AI."

## Overview

da Realest Geek is a comprehensive SaaS platform designed for residential real estate agents, teams, and independent brokers. It combines AI-powered lead capture, smart scheduling, automated marketing, and CRM functionality to help agents close more deals efficiently.

## Features

- 🤖 **AI Lead Capture & Qualification** - Embeddable chat widget with intelligent lead scoring
- 📅 **Smart Scheduling** - AI-powered booking with calendar integration
- 🎨 **AI Marketing Studio** - Auto-generate listings, social media content, and campaigns
- 📊 **Advanced CRM** - Pipeline management with automation workflows
- 📄 **Document Management** - Templates and e-signature integration
- 🔍 **Analytics & Insights** - AI-driven performance analytics
- 👥 **Team Collaboration** - Multi-user support with role-based permissions

## Tech Stack

### Frontend
- **Framework:** Next.js 14 (App Router) + React 18
- **Language:** TypeScript
- **Styling:** Tailwind CSS + shadcn/ui
- **Animation:** Framer Motion
- **State Management:** TanStack Query + Zustand
- **Forms:** React Hook Form + Zod validation

### Backend
- **Runtime:** Node.js + TypeScript
- **Framework:** NestJS
- **Database:** PostgreSQL + Redis
- **ORM:** Prisma
- **Authentication:** Auth0/Clerk
- **File Storage:** AWS S3 compatible

### AI & Integrations
- **LLM:** OpenAI GPT-4
- **Embeddings:** OpenAI text-embedding-ada-002
- **Image Processing:** Replicate SDXL
- **Email:** SendGrid
- **SMS:** Twilio
- **Calendar:** Google Calendar + Microsoft 365
- **Maps:** Google Maps Platform
- **Payments:** Stripe

## Quick Start

### Prerequisites

You'll need the following API keys:

- **OpenAI API Key** - For AI features
- **Google Maps API Key** - For location services
- **Google Calendar API** - For calendar integration
- **Microsoft Graph API** - For Outlook calendar
- **Twilio Account SID & Auth Token** - For SMS/voice
- **SendGrid API Key** - For email delivery
- **Stripe API Keys** - For payments
- **Auth0 Domain & Client ID** - For authentication
- **AWS S3 Credentials** - For file storage

### Installation

1. **Clone and setup:**
```bash
cd da-realest-geek
npm install
```

2. **Environment setup:**
```bash
cp .env.example .env.local
# Fill in your API keys in .env.local
```

3. **Database setup:**
```bash
npm run db:setup
npm run db:migrate
npm run db:seed
```

4. **Start development:**
```bash
npm run dev
```

## Project Structure

```
da-realest-geek/
├── apps/
│   ├── web/                 # Next.js frontend
│   └── api/                 # NestJS backend
├── packages/
│   ├── ui/                  # Shared UI components
│   ├── database/            # Prisma schema & migrations
│   ├── types/               # Shared TypeScript types
│   └── config/              # Shared configuration
├── docs/                    # Documentation
└── tools/                   # Build tools & scripts
```

## Deployment

- **Frontend:** Vercel (recommended) or Netlify
- **Backend:** Fly.io, Render, or AWS ECS
- **Database:** Supabase, PlanetScale, or AWS RDS
- **Redis:** Upstash or AWS ElastiCache

## License

Proprietary - All rights reserved

## Support

For support, email support@darealestgeek.com or visit our documentation.