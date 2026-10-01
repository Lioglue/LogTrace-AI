# LogTrace AI

## Cybersecurity Log Analysis and Incident Investigation Platform

LogTrace AI is a web-based platform that transforms raw security logs into clear, understandable Attack Stories. It automatically parses logs, detects suspicious activity, correlates related events, and reconstructs possible incidents into chronological investigation timelines.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Problem Being Solved](#problem-being-solved)
3. [Main Features](#main-features)
4. [SIEM Comparison](#siem-comparison)
5. [Architecture](#architecture)
6. [Technology Stack](#technology-stack)
7. [Project Structure](#project-structure)
8. [Installation](#installation)
9. [Environment Variables](#environment-variables)
10. [Database Setup](#database-setup)
11. [Running Locally](#running-locally)
12. [Loading Demo Data](#loading-demo-data)
13. [Example Workflow](#example-workflow)
14. [API Documentation](#api-documentation)
15. [How Detection and Correlation Work](#how-detection-and-correlation-work)
16. [Future Improvements](#future-improvements)

---

## Project Overview

LogTrace AI helps security analysts understand how separate log events may be connected by automatically:

- Parsing raw log data from multiple sources
- Normalizing events into standard types
- Detecting suspicious activity using explainable rules
- Correlating related events with scoring
- Clustering events into potential incidents
- Calculating risk and confidence scores
- Generating chronological Attack Stories

---

## Problem Being Solved

Traditional log monitoring produces many individual events and alerts. A security analyst must manually investigate whether events are connected. For example:

- Multiple failed logins
- A successful login from the same source
- Sensitive resource access

These appear as separate alerts. LogTrace AI automatically identifies related events and presents them as a clear investigation timeline.

---

## Main Features

- **Log Parsing**: Automatic format detection and parsing for auth, web, firewall, application, system, and generic logs
- **Event Normalization**: Standardized event types across different sources
- **Detection Engine**: Rule-based suspicious activity detection with explainable alerts
- **Time-Window Analysis**: Configurable time windows for threshold and sequence detection
- **Correlation Engine**: Multi-factor event correlation with scoring
- **Incident Clustering**: Groups strongly correlated events into incidents
- **Risk Scoring**: 0-100 risk score based on event severity, correlation, and context
- **Incident Confidence**: Separate metric for evidence strength
- **Attack Story Generation**: Chronological reconstruction of investigation narratives
- **Incident Replay**: Step-by-step event replay with controls
- **Dashboard**: Real-time security overview with charts
- **Log Explorer**: Searchable, filterable event browser
- **Analytics**: Comprehensive event and incident analytics
- **Authentication**: JWT-based user authentication
- **Demo Data**: Pre-built scenarios for testing

---

## SIEM Comparison

| Feature | Traditional SIEM | LogTrace AI |
|---------|-----------------|-------------|
| Log Collection | Yes | Yes |
| Centralized Storage | Yes | Yes |
| Monitoring | Yes | Focused |
| Alerting | Yes | Yes (explainable) |
| Event Correlation | Yes | Yes (scored) |
| Incident Clustering | Varies | Core Feature |
| Risk Scoring | Varies | Core Feature |
| Attack Story | No | Core Feature |
| Compliance | Yes | No |

LogTrace AI is not a complete SIEM replacement. It focuses specifically on making event relationships and incident reconstruction easier to understand.

---

## Architecture

```
React + TypeScript Frontend
            |
       REST API
            |
      FastAPI Backend
            |
    Log Processing Engine
            |
       Log Parsers
            |
    Event Normalization
            |
    Detection Engine
            |
  Suspicious Event Alerts
            |
   Correlation Engine
            |
    Incident Clustering
            |
 Risk + Confidence Scoring
            |
 Attack Story Generator
            |
       Database
            |
 Dashboard + Investigation UI
```

---

## Technology Stack

### Frontend
- React 18
- TypeScript
- Vite
- Tailwind CSS
- React Router
- Recharts
- Lucide React Icons

### Backend
- Python 3.10+
- FastAPI
- SQLAlchemy
- Pydantic
- JWT Authentication
- Passlib (bcrypt)

### Database
- SQLite (default, for development)
- PostgreSQL (supported via environment variable)

---

## Project Structure

```
logtrace-ai/
├── frontend/
│   ├── src/
│   │   ├── components/     # Reusable UI components
│   │   ├── pages/          # Application pages
│   │   ├── layouts/        # Layout components
│   │   ├── services/       # API service layer
│   │   ├── context/        # React context
│   │   ├── types/          # TypeScript types
│   │   ├── utils/          # Utility functions
│   │   ├── App.tsx
│   │   └── main.tsx
│   ├── package.json
│   └── vite.config.ts
│
├── backend/
│   ├── app/
│   │   ├── api/            # API route handlers
│   │   ├── models/         # Database models
│   │   ├── schemas/        # Pydantic schemas
│   │   ├── services/       # Business logic
│   │   ├── parsers/        # Log parsers
│   │   ├── detection/      # Detection engine
│   │   ├── correlation/    # Correlation engine
│   │   ├── incident/       # Incident clustering
│   │   ├── story/          # Attack story generator
│   │   ├── database/       # Database configuration
│   │   ├── config/         # App settings
│   │   └── main.py
│   ├── tests/              # Test files
│   └── requirements.txt
│
├── sample_logs/            # Example log files
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## Installation

### Prerequisites

- Python 3.10+
- Node.js 18+
- pip
- npm

### Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e .

# Or without editable mode
pip install fastapi uvicorn sqlalchemy pydantic pydantic-settings python-jose passlib python-multipart bcrypt python-dotenv psycopg2-binary httpx
```

### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install
```

---

## Environment Variables

Copy `.env.example` to `.env` in the backend directory:

```bash
cp .env.example backend/.env
```

Key variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Database connection string | `sqlite:///./logtrace.db` |
| `SECRET_KEY` | JWT signing key | Required |
| `ALGORITHM` | JWT algorithm | `HS256` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Token expiry | `1440` |
| `CORS_ORIGINS` | Allowed frontend origins | `["http://localhost:5173"]` |

---

## Database Setup

The application uses SQLAlchemy and will automatically create tables on startup.

For SQLite (default): No setup required.

For PostgreSQL:

1. Create a PostgreSQL database
2. Update `DATABASE_URL` in `.env`:
   ```
   DATABASE_URL=postgresql://user:password@localhost:5432/logtrace
   ```

---

## Running Locally

### Start Backend

```bash
cd backend
python -m uvicorn app.main:app --reload --port 8000
```

### Start Frontend

```bash
cd frontend
npm run dev
```

The frontend will be available at `http://localhost:5173` and will proxy API requests to the backend at `http://localhost:8000`.

---

## Loading Demo Data

1. Register or login to the application
2. Navigate to the Dashboard
3. Click "Load Demo Data"
4. This creates 4 scenarios:
   - Normal traffic (no incident expected)
   - Repeated failed logins
   - Failed logins followed by success
   - Full incident (brute force + resource access)

---

## Example Workflow

1. **Upload Logs**: Go to Upload Logs, drag and drop a .log file
2. **Automatic Processing**: The system parses, normalizes, detects, correlates, and clusters events
3. **View Dashboard**: Check the dashboard for new suspicious events and incidents
4. **Explore Events**: Use the Log Explorer to search and filter through parsed events
5. **Investigate Incidents**: Click on an incident to see its full investigation page
6. **View Attack Story**: Review the chronological timeline of how the incident may have unfolded
7. **Replay**: Use the replay feature to walk through events step by step
8. **Update Status**: Mark incidents as investigating, resolved, or closed

---

## API Documentation

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Create a new account |
| POST | `/api/auth/login` | Login and receive JWT token |
| GET | `/api/auth/me` | Get current user info |

### Logs

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/logs/upload` | Upload a log file |
| GET | `/api/logs` | List uploaded log files |
| GET | `/api/logs/{id}` | Get a specific log file |

### Events

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/events` | List events with filters |
| GET | `/api/events/{id}` | Get event details |

### Incidents

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/incidents` | List incidents |
| GET | `/api/incidents/{id}` | Get incident details |
| PATCH | `/api/incidents/{id}` | Update incident status |
| GET | `/api/incidents/{id}/story` | Get attack story |

### Analytics

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/analytics/dashboard` | Dashboard analytics |
| GET | `/api/analytics/events` | Event analytics |

### Demo

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/demo/load` | Load demo data |

---

## How Detection and Correlation Work

### Detection Rules

1. **High Severity Events**: Events with high or critical severity trigger alerts
2. **Privilege Changes**: Any privilege change is flagged
3. **Sensitive Resource Access**: Access to configured sensitive resources is detected
4. **Repeated Failures**: Threshold-based detection (default: 5 failures in 5 minutes from same IP)
5. **Failed-Then-Success Sequence**: Multiple failures followed by a success from the same source

### Correlation Scoring

Events are compared on multiple factors:

- Same IP address: +30 points
- Same username: +25 points
- Same hostname: +15 points
- Same source system: +10 points
- Within 5 minutes: +20 points
- Within 15 minutes: +10 points
- Related event sequence: +30 points

Events with a total score >= 50 (configurable) are considered related.

### Risk Score

Risk is calculated from:
- Event severity weights
- Correlation strength
- Sensitive resource involvement
- Suspicious event sequences
- Number of affected systems

### Incident Confidence

Confidence measures evidence strength separately from risk:
- Correlation factor count and strength
- Consistency of event sequence
- Amount of supporting evidence

---

## Future Improvements

- Custom detection rule editor
- Threat intelligence integration
- Anomaly detection using historical baselines
- Email/webhook notifications
- CSV/PDF report export
- Multi-user collaboration
- API key authentication
- Rate limiting
- Log retention policies
- Real-time log streaming
- Custom dashboards
- Machine learning-based anomaly detection
