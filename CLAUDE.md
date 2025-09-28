# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**AI SOC Framework (ASF)** is an open-source, AI Agent-based SOC automation framework designed for security alert processing and analysis. It combines webhook-based alert pipelines, Redis Streams for message queuing, and LLM-powered automation modules/playbooks to automate security operations at scale.

**Key Architecture Components:**
- **Django REST API** - HTTP server for webhooks and API endpoints (port 7000)
- **Redis Streams** - Message queuing system for alert processing pipelines
- **Module Engine** - Dynamic module loader for processing alert streams
- **Playbook Framework** - Job scheduling system for automation tasks
- **MCP Server** - Model Context Protocol integration (port 7001)
- **LLM Integration** - Support for OpenAI and Ollama with Langchain/Langgraph

## Quick Commands

### Development Setup
```bash
# Activate virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -e .
```

### Running the Application

**Main Web Server (Django + ASGI):**
```bash
# Using uvicorn (default, configured in uvicorn.toml)
uvicorn ASF.asgi:application --config uvicorn.toml

# Or directly with uvicorn
uvicorn ASF.asgi:application --host 0.0.0.0 --port 7000
```

**MCP Server (Model Context Protocol):**
```bash
python mcpserver.py
# Runs on http://0.0.0.0:7001/{uuid}/sse
```

**Django Management Commands:**
```bash
# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Development server
python manage.py runserver
```

### Testing & Debugging

**Debug Individual Playbooks/Modules:**
```bash
# Run a single playbook directly
python PLAYBOOKS/Debug_DFMEA_Gen_Automation.py

# Debug modules with redis inspection
python Test/redis_read.py  # Read from Redis streams
python Test/nocoly_debug.py  # Debug Nocoly integration
```

**Redis Stream Inspection:**
- Read streams: `Test/redis_read.py`, `Test/redis_read_1.py`
- Write test messages: `Test/redis_write.py`
- View with Redis Insight: http://serverip:8001 (default password in CONFIG)

## Configuration

### CONFIG.py (Required)
Copy `CONFIG.example.py` to `CONFIG.py` and configure:
- **Redis**: `REDIS_URL`, `REDIS_STREAM_STORE_DAYS`
- **LLM**: `LLM_TYPE` (openai/ollama), `LLM_API_KEY`, `LLM_BASE_URL`, `LLM_MODEL`
- **Dify**: `DIFY_BASE_URL`, `DIFY_API_KEY` (dict mapping app names to keys)
- **SIRP (AI SOAR)**: `SIRP_URL`, `SIRP_APPKEY`, `SIRP_SIGN`
- **Security**: `ASF_TOKEN` for playbook API access

### Django Settings
- Located in `ASF/settings.py`
- Imports `REDIS_URL` from `CONFIG.py`
- Logging configured to `Docker/log/django.log`
- Uses Django authentication middleware

## Architecture Deep Dive

### Alert Processing Pipeline

1. **Webhook Ingestion** (`Forwarder/views.py`):
   - `WebhookSplunkView`: Receives Splunk alerts
   - `WebhookKibanaView`: Receives Elasticsearch/Kibana alerts
   - `WebhookNocolyMailView`: Receives notifications from SIRP
   - All webhooks route to Redis Streams by rule/search name

2. **Module Engine** (`Lib/engine.py`):
   - Dynamically loads all `.py` files from `MODULES/` directory
   - Spawns threads based on `Module.THREAD_NUM` class variable
   - Continuously runs `module.run()` method in loop, consuming from Redis Streams
   - Handles module reloading without server restart

3. **Module Development** (`Lib/basemodule.py`):
   - Inherit from `BaseAPI` or `LanggraphAPI`
   - Required: Implement `run()` method and set `THREAD_NUM`
   - API: `read_message()` (reads from Redis Stream), `logger` (logging), `get_dify_api_key()`
   - Debug mode: Set `self.debug_message_id` to replay specific messages from Redis

4. **Playbooks** (`Lib/baseplaybook.py`):
   - Inherit from `BasePlaybook` with `RUN_AS_JOB = True/False`
   - Can be triggered via API endpoint `POST /api/v1/automation/playbook`
   - Use APScheduler for background job execution
   - Access parameters via `self.param(key, default)`

### Core Components

**Redis Stream API** (`Lib/redis_stream_api.py`):
- `send_message(stream_key, message)` - Send to Redis Stream
- `read_message(stream_key, consumer_group, consumer_name)` - Consume from Stream
- `clean_redis_stream(max_age_days)` - Cleanup old messages

**External Integrations** (`Lib/External/`):
- `nocolyapi.py` - SIRP (AI SOAR) alert creation/update
- `sirpapi.py` - SIRP workflow integration
- `dify.py` - Dify workflow automation
- `llmapi.py` - LLM function calling

**Data Models** (`Core/models.py`):
- Custom Django fields: `DiyListField`, `DiyDictField` for flexible JSON storage
- RESTful serializers in `Core/serializers.py`

**Authentication** (`Core/Handle/`):
- Token-based auth via `ASF_TOKEN` in CONFIG
- User model integration via Django auth
- Current user API: `GET /api/currentUser`

### Background Services

**Monitor/MainMonitor** (`Lib/montior.py`):
- Starts the Module Engine
- Cleans up old Redis Stream messages periodically (every 5 minutes)
- Sets up API token user for webhook processing
- Called from application startup (see commented code in `ASF/urls.py`)

**APScheduler** (`Lib/apsmodule.py`):
- Schedules playbook execution as background jobs
- UUID-based job tracking and result caching
- Singleton pattern for global access

## Directory Structure

```
ASF/                    # Django project configuration
├── settings.py        # Django settings, logging config
├── asgi.py            # ASGI entry point
├── wsgi.py            # WSGI entry point
└── urls.py            # API route registration

Core/                   # Core API and auth
├── models.py          # Django models, custom fields
├── views.py           # Auth/user endpoints
├── serializers.py     # DRF serializers
└── Handle/            # Auth handlers

Forwarder/             # Webhook receivers
└── views.py           # Splunk, Kibana, Nocoly webhooks

Automation/            # Playbook management
├── views.py           # Playbook API endpoint
└── Handle/
    └── playbook.py    # Playbook execution logic

MODULES/               # Alert processing modules (auto-loaded by Engine)
└── *.py               # Custom module implementations

PLAYBOOKS/             # One-off automation scripts
└── *.py               # Playbook implementations

Lib/                   # Core utilities
├── engine.py          # Dynamic module loader
├── basemodule.py      # Module base class
├── baseplaybook.py    # Playbook base class
├── redis_stream_api.py # Redis Stream wrapper
├── redis_client.py    # Redis connection management
├── llmfunc.py         # LLM function definitions
├── apsmodule.py       # Job scheduler
├── montior.py         # Background monitor


Test/                  # Testing and debugging utilities
├── redis_read.py      # Read Redis Streams
├── nocoly_debug.py    # Debug SIRP integration
└── *.py               # Other test scripts

Docker/                # Docker configuration
├── log/               # Log files directory
└── mock/              # Mock services for testing
    ├── alert.py       # Mock alert generator
    └── nocoly_debug.py # Mock Nocoly API
```

## Key Patterns & Concepts

### Module Development Pattern
Every module needs:
```python
from Lib.basemodule import BaseAPI

class Module(BaseAPI):
    THREAD_NUM = 2  # Number of parallel threads

    def run(self):
        message = self.read_message()
        if message:
            # Process alert
            self.logger.info(f"Processing: {message}")
```

### Playbook Pattern
```python
from Lib.baseplaybook import BasePlaybook

class YourPlaybook(BasePlaybook):
    RUN_AS_JOB = True

    def run(self):
        param = self.param('key_name', default='value')
        # Automation logic
```

### Redis Stream Naming
- **Stream keys match module/playbook names**: Stream key = module filename (without .py)
- Messages flow: `Forwarder (webhook) → Redis Stream (rule_name) → Module (stream_key=module_name)`
- Consumer groups enable multi-threaded consumption without message loss

### LLM Integration
- Config determines provider: `LLM_TYPE = 'openai'` or `'ollama'`
- Langchain/Langgraph for agent orchestration
- Dify for pre-built workflow automation
- Function calling via `Lib/llmfunc.py`

## Common Development Tasks

**Create a New Alert Processing Module:**
1. Create `MODULES/MyAlert.py` inheriting from `BaseAPI` or `LanggraphAPI`
2. Implement `run()` to call `self.read_message()`
3. Set `THREAD_NUM` for concurrency
4. Module will auto-load; matching webhook sends to Redis stream named "MyAlert"

**Create a Playbook:**
1. Create `PLAYBOOKS/MyPlaybook.py` inheriting from `BasePlaybook`
2. Implement `run()` method
3. Trigger via API: `POST /api/v1/automation/playbook` with `{"playbook": "MyPlaybook", ...}`

**Debug a Module:**
1. Add print statements or set `self.debug_message_id` in module
2. Use `Test/redis_read.py` to find message IDs
3. Run module directly: `python MODULES/ModuleName.py` with debug mode enabled

**Add Third-Party Integration:**
1. Create wrapper in `Lib/External/` following pattern of `nocolyapi.py`
2. Import and use in modules/playbooks
3. Add config credentials to `CONFIG.py`

## Deployment & Docker

**Docker Services** (in `Docker/mock/`):
- Mock Splunk alert service
- Mock Nocoly/SIRP service
- Alert generation for testing

**Key Ports:**
- `7000` - Main Django/ASGI server
- `7001` - MCP server
- `6379` - Redis (external dependency)
- `8001` - Redis Insight UI (optional, for debugging)

**Logs:**
- Django: `Docker/log/django.log`
- Standard output for module/playbook execution
