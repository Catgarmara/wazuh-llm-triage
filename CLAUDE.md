# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Status

### What This Is
A functional SOC AI chat application with alert processing and OSINT enrichment.

### Core Features
- **Multi-Model AI Chat**: DeepSeek and Gemini support
- **Alert Processing Pipeline**: Webhook → SQLite → AI → OSINT → SQLite
- **OSINT Enrichment**: Perplexity API for threat intelligence
- **OpenSearch Queries**: Separate feature for querying security data
- **Session Management**: Chat history with 24-hour expiration

### Alert Processing Flow
1. Alert arrives at `/opensearch/alert` webhook (poorly named - not related to OpenSearch)
2. Saved to SQLite (`alerts.db`)
3. AI performs initial analysis and extracts IoCs
4. Perplexity provides OSINT on those IoCs
5. AI performs final analysis with all context
6. SQLite updated with complete analysis
7. Returns acknowledgment (200 if complete, 202 if AI timed out)

#### Environment Variables (Required)
```bash
# AI Provider
DEEPSEEK_API_KEY=your-deepseek-key

# OSINT Enrichment
PERPLEXITY_API_KEY=pplx-xxxxx

# OpenSearch Connection (for querying)
OPENSEARCH_HOST=your-opensearch.company.com
OPENSEARCH_PORT=443
OPENSEARCH_USER=your-username
OPENSEARCH_PASSWORD=your-password
OPENSEARCH_SSL=true
OPENSEARCH_INDEX=waf-*
```

#### Anti-Patterns to Avoid
- NO abstract factory builders or over-engineering
- NO comprehensive frameworks - keep it simple
- NO enterprise bullshit or buzzwords
- Just write simple working code

## Development Commands

### Python Environment
```bash
# Install dependencies
pip install -r requirements.txt

# Run application
python3 app.py

# Development server (Flask auto-reload)
python3 dev-server.py

# Run tests
python3 manual_test.py           # Interactive testing
python3 demo_ai_clients.py       # Test AI model functionality
python3 integration_example.py   # Integration examples
python3 test_flask_integration.py # Flask integration tests

# Security analysis tests
python3 security_analyzer_test.py
python3 test_diverse_alert_structures.py
```

### JavaScript/Frontend
```bash
# Install Node dependencies
npm install

# Run Jest tests
npm test

# Development commands (placeholder implementations)
npm run dev       # Runs python app.py
npm run build     # Would run CSS/JS build
npm run lint      # Would run linting
npm run serve     # Static file server on port 8080
```

## Architecture Overview

### SOC AI Chat System with Alert Processing
Flask-based chat system with AI analysis, OSINT enrichment, and SIEM integration.

#### Core Components

**Backend (Python)**
- `app.py`: Main Flask application (~450 lines) with alert webhook
- `ai_handler.py`: AI analysis with 3-phase flow (initial → OSINT → final)
- `alert_store.py`: SQLite storage with save/update/retrieve functions
- `ai_clients.py`: DeepSeek/Gemini provider abstraction
- `session_manager.py`: Chat session management
- `connectors/opensearch.py`: Simple OpenSearch query interface (179 lines)
- `security_analyzer.py`: Legacy security analysis (mostly unused)
- `config.py`: Simple environment configuration

**Frontend (JavaScript)**
- `static/js/main.js`: Core frontend application logic
- `static/js/modules.disabled/`: Disabled module system (Task 8 cleanup - DO NOT re-enable)
- Session management, message rendering, and AI model switching in main.js
- CSS organized in `static/css/` with component-based structure

#### Connector Pattern
Simple connector pattern in `connectors/`:
- `base.py`: Base connector interface (~50 lines)
- `opensearch.py`: OpenSearch implementation (~150 lines)

### Key Design Patterns

1. **Simple Direct Instantiation**: No factory patterns, just direct class usage
2. **Connector Pattern**: Clean abstraction for SIEM integrations
3. **Session-Based Memory**: In-memory conversation storage with automatic cleanup
4. **Simple Caching**: Basic in-memory caching where needed
5. **Basic Error Handling**: Try/catch with simple retry logic

### API Endpoints

**Core Chat**
- `GET /`: Serve main chat interface
- `POST /chat`: Main chat endpoint with session management
- `GET /health`: Health check with system status

**Alert Processing (NEW)**
- `POST /opensearch/alert`: Webhook for SIEM alerts (POST/PUT/PATCH)
- `GET /opensearch/alert/<id>`: Retrieve specific alert with analysis
- `GET /security/alerts`: List recent alerts from database
- `POST /security/analyze`: Analyze security alerts

**OpenSearch Integration**
- `GET /opensearch/indices`: List available indices
- `POST /opensearch/query`: Execute OpenSearch queries
- `GET /opensearch/integration/status`: Connection status

**SOC Features**
- `POST /soc/analyze`: SOC-specific analysis with templates
- `GET /soc/templates`: Available SOC analysis templates

### Environment Configuration

Required environment variables (in `.env`):
```bash
DEEPSEEK_API_KEY=sk-your-deepseek-key
GEMINI_API_KEY=your-gemini-key  # Optional
```

Optional configuration:
```bash
FLASK_HOST=127.0.0.1
FLASK_PORT=5000
LOG_LEVEL=INFO
```

### Testing Strategy

1. **Python Testing**: Manual test scripts for integration testing
2. **JavaScript Testing**: Jest with jsdom for frontend components
3. **Test Coverage**: Focus on critical paths (AI client integration, error handling)
4. **Test Files**: Located in `__TESTS/` directory

### Important Notes

1. **Module System**: The `static/js/modules.disabled/` directory contains a disabled module system. DO NOT re-enable without careful consideration - it was disabled in Task 8 due to complexity issues.

2. **Database File**: Single SQLite database:
   - `alerts.db`: Consolidated alerts database

3. **AI Provider Keys**: DeepSeek API key is required for basic functionality. Gemini is optional but provides multi-model support.

4. **Session Management**: Conversations are stored in-memory with 24-hour expiration and 10-message history limit to prevent token overflow.

5. **Simple Performance**: Basic caching and connection reuse.

6. **Error Handling**: Simple try/catch with basic retry logic.

### Current Limitations

1. **Chat endpoint cannot automatically query OpenSearch** - User must manually use `/opensearch/query` endpoint
2. **Alert webhook poorly named** - `/opensearch/alert` has nothing to do with OpenSearch, just receives alerts
3. **No automatic OpenSearch integration in chat** - AI cannot fetch real security data during conversations

### File Organization

```
ba-new/
├── app.py                    # Main Flask application (~450 lines)
├── ai_handler.py             # AI analysis with OSINT integration
├── alert_store.py            # SQLite alert storage (CRUD operations)
├── ai_clients.py             # Simple DeepSeek/Gemini clients (~285 lines)
├── session_manager.py        # Chat session management
├── connectors/               
│   └── opensearch.py        # OpenSearch query interface (179 lines)
├── static/                   # Frontend assets
├── alerts.db                # SQLite database for alerts
├── archive/                 # Old/backup files
└── .env                     # Environment variables