# SOC AI Chat with Alert Processing

A Flask-based Security Operations Center (SOC) AI chat application with alert processing, OSINT enrichment, and SIEM integration.

## 🚀 Current Features

- **Multi-Model AI Chat**: DeepSeek and Google Gemini support with session management
- **Alert Processing Pipeline**: Webhook → SQLite → AI Analysis → OSINT → Final Report
- **OSINT Enrichment**: Perplexity API integration for threat intelligence
- **OpenSearch Integration**: Query interface for security data (console proxy pattern)
- **3-Phase AI Analysis**: Initial analysis → IoC extraction → OSINT lookup → Final analysis
- **SQLite Alert Storage**: Persistent storage with update capabilities
- **Session Management**: Conversation history with 24-hour expiration
- **Health Monitoring**: System status and component health checks

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Required API keys (see .env.example)

### Installation

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Set up environment**:
   ```bash
   cp .env.example .env
   # Edit .env and add your API keys:
   # DEEPSEEK_API_KEY=your-key (required)
   # PERPLEXITY_API_KEY=pplx-xxxx (for OSINT)
   # OPENSEARCH_HOST=your-opensearch.com (for queries)
   ```

3. **Run the application**:
   ```bash
   python3 app.py
   ```

4. **Open in browser**: http://127.0.0.1:5000

### Testing
```bash
# Interactive testing
python3 manual_test.py

# Test model functionality  
python3 demo_ai_clients.py
```

## 🚨 Alert Processing (NEW)

### Webhook for SIEM Alerts
The application can receive and process security alerts from any SIEM:

```bash
# Send alert to webhook
curl -X POST http://localhost:5000/opensearch/alert \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.1.100",
    "event_type": "ssh_brute_force",
    "severity": "high"
  }'

# Retrieve processed alert
curl http://localhost:5000/opensearch/alert/1
```

**Processing Flow:**
1. Alert received via webhook
2. Saved to SQLite database
3. AI performs initial analysis
4. IoCs extracted and sent to Perplexity for OSINT
5. Final analysis with threat intelligence
6. Complete report stored in database

## ⚙️ Configuration

### Required Environment Variables
```bash
DEEPSEEK_API_KEY=your-deepseek-key         # AI provider
PERPLEXITY_API_KEY=pplx-xxxx               # OSINT enrichment
OPENSEARCH_HOST=your-opensearch.com        # SIEM queries
OPENSEARCH_USER=your-username
OPENSEARCH_PASSWORD=your-password
```

## 🔌 API Reference

### Basic Chat
```bash
curl -X POST http://localhost:5000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello", "model": "deepseek"}'
```

### Streaming Chat
```bash
curl -X POST http://localhost:5000/chat/stream \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello", "model": "gemini", "stream": true}'
```

### Health Check
```bash
curl http://localhost:5000/health
```

### SOC Features
The application includes Security Operations Center (SOC) templates for incident analysis:

```bash
# Get available SOC templates
curl http://localhost:5000/soc/templates

# Analyze security incident (text-only)
curl -X POST http://localhost:5000/soc/analyze \
  -H "Content-Type: application/json" \
  -d '{"incident_data": "Suspicious activity detected", "template": "incident_analysis"}'

# Analyze with live SIEM data (OpenSearch console proxy)
curl -X POST http://localhost:5000/soc/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "incident_data": "Suspicious login activity", 
    "opensearch_query": {"query": {"match": {"event.type": "authentication"}}, "size": 10}
  }'

# Uses console proxy pattern: https://your-opensearch:443/api/console/proxy?path=/logs-*/_search&method=POST
```

## 🛠 Project Structure

### Project Structure
```
ba-new/
├── app.py                    # Main Flask application (~450 lines)
├── ai_handler.py             # AI analysis with OSINT integration
├── alert_store.py            # SQLite alert storage (CRUD operations)
├── session_manager.py        # Chat session management
├── ai_clients.py             # DeepSeek/Gemini provider abstraction
├── connectors/               
│   └── opensearch.py        # OpenSearch query interface (179 lines)
├── static/                   # Frontend assets
│   ├── js/main.js          # Chat interface logic
│   └── css/                # Stylesheets
├── alerts.db                # SQLite database for alerts
├── .env.example             # Environment template with all options
└── CLAUDE.md                # AI coding guidelines
```


## 🔧 Development

### Running Tests
```bash
# Manual testing script
python3 manual_test.py

# Multi-model demonstration
python3 demo_ai_clients.py

# Integration examples
python3 integration_example.py

# Configuration validation
python3 validate_deployment.py development
```

### API Routes

#### Core Application Routes
- `GET /` - Web chat interface and static file serving
- `POST /chat` - AI chat endpoint with model selection
- `GET /health` - Application health check and dependency status

#### Security & SOC Routes  
- `POST /security/analyze` - Security incident analysis
- `GET /security/alerts` - Retrieve stored alerts for audit
- `POST /soc/analyze` - SOC analysis with template support
- `GET /soc/templates` - Available SOC analysis templates

#### OpenSearch Integration Routes
- `GET /opensearch/indices` - Available OpenSearch indices discovery
- `POST /opensearch/query` - Execute OpenSearch queries via console proxy  
- `GET /opensearch/integration/status` - OpenSearch connector health check

## 🔒 Security Features

- **Input Validation**: All user inputs are validated and sanitized
- **API Key Security**: Secure API key management via environment variables
- **SOC Templates**: Pre-built security analysis templates
- **Alert Storage**: SQLite storage for security alerts
- **Session Security**: Secure conversation management with automatic cleanup

## 📄 Documentation

- **[README.md](README.md)** - This file (project overview and quick start)
- **[DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)** - Complete deployment instructions
- **[CONFIGURATION_REFERENCE.md](CONFIGURATION_REFERENCE.md)** - Configuration options reference
- **[CLAUDE.md](CLAUDE.md)** - Development guidance and architecture

## 🗺️ Roadmap

- Multi-model AI chat (DeepSeek, Gemini)
- SOC templates and analysis
- OpenSearch integration for security data
- Additional SIEM connectors (planned)

## 📄 License

This project is provided as-is for educational and development purposes.