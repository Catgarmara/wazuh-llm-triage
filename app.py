#!/usr/bin/env python3
"""
Flask backend for SOC AI chat application - Refactored to ~500 lines

Core functionality only:
- Multi-model AI chat with session management
- Security analysis with OpenSearch integration  
- SOC-focused endpoints for threat analysis
- Health monitoring and configuration validation

All complex logic delegated to specialized modules.
"""

import os
import json
import logging
from datetime import datetime
from flask import Flask, send_from_directory, jsonify, request
from flask_cors import CORS
from dotenv import load_dotenv

# Import our modules
from ai_handler import init_ai_client, chat_completion, analyze_security_alert
from session_manager import cleanup_expired, get_session_stats, get_or_create_session, add_message, get_history
from connectors.opensearch import query_opensearch, get_available_indices
# from security_analyzer import analyze_alert  # REMOVED - using ai_handler instead
from alert_store import save_alert, get_alert_by_id
from config import load_config, get_config

# Load environment and configuration
load_dotenv()
load_config()
config = {}

# Initialize Flask app
app = Flask(__name__, static_folder='static')
CORS(app, origins=['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:5000'])

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# SOC Templates for structured analysis
SOC_TEMPLATES = {
    'incident_analysis': {
        'prompt': 'Analyze this security incident. Provide threat level, impact, and recommended actions.',
        'fields': ['threat_level', 'impact_assessment', 'recommended_actions']
    },
    'threat_hunting': {
        'prompt': 'Examine for threats and anomalies. Identify IOCs and hunting hypotheses.',
        'fields': ['iocs_identified', 'threat_hypotheses', 'hunting_queries']
    },
    'executive_summary': {
        'prompt': 'Create executive summary. Focus on business impact and required actions.',
        'fields': ['executive_summary', 'business_impact', 'risk_level']
    }
}

# Initialize components
print("🔧 Initializing SOC AI Chat Application...")

# Database initialization handled automatically by alert_store.py

# Initialize AI client
try:
    if init_ai_client('deepseek'):
        print("✅ AI client initialized")
    else:
        print("⚠️ AI client failed to initialize")
except Exception as e:
    logger.error(f"AI client error: {e}")

print("🚀 Application ready")


# ROUTES (10-12 routes total)

@app.route('/')
def homepage():
    """Serve homepage."""
    try:
        return send_from_directory(app.static_folder, 'index.html')
    except FileNotFoundError:
        return jsonify({'error': 'Homepage not found'}), 404


@app.route('/chat', methods=['POST'])
def chat():
    """Simple chat endpoint - delegates to ai_handler for processing."""
    if not request.is_json:
        return jsonify({'error': 'Request must be JSON'}), 400
    
    try:
        data = request.get_json()
        message = data.get('message', '').strip()
        
        if not message:
            return jsonify({'error': 'Message is required'}), 400
        
        if len(message) > 1000:
            return jsonify({'error': 'Message too long (max 1000 chars)'}), 400
        
        # Get session and model
        session_id = data.get('session_id')
        model = data.get('model', 'deepseek')
        
        # Switch AI client if needed
        from ai_handler import get_current_provider
        current_provider = get_current_provider()
        if model.lower() != str(current_provider).lower():
            logger.info(f"Switching AI provider from {current_provider} to {model}")
            init_ai_client(model)
        
        # Get or create session
        session_id, session_data = get_or_create_session(session_id, model)
        
        # Add user message to session
        add_message(session_id, 'user', message)
        
        # Get conversation history
        messages = get_history(session_id)
        
        # Call AI handler
        result = chat_completion(messages, session_id=session_id, include_soc_context=True)
        
        # Add assistant response to session
        add_message(session_id, 'assistant', result['response'], 
                   model=result.get('model'), provider=result.get('provider'))
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Chat error: {e}")
        return jsonify({'error': 'Chat processing failed'}), 500


@app.route('/health')
def health():
    """Comprehensive health check with OpenSearch status."""
    cleanup_expired()
    session_stats = get_session_stats()
    
    # Check OpenSearch connectivity
    opensearch_status = 'unknown'
    try:
        indices = get_available_indices()
        opensearch_status = 'connected' if indices else 'disconnected'
    except:
        opensearch_status = 'error'
    
    # Environment validation
    env_valid = bool(os.getenv('DEEPSEEK_API_KEY'))
    
    health_data = {
        'status': 'healthy' if env_valid else 'degraded',
        'timestamp': datetime.now().isoformat(),
        'components': {
            'ai_client': 'active',  # Simplified check
            'opensearch': opensearch_status,
            'database': 'active',
            'sessions': session_stats['total_sessions']
        },
        'environment': {
            'deepseek_key': bool(os.getenv('DEEPSEEK_API_KEY')),
            'opensearch_host': bool(os.getenv('OPENSEARCH_HOST')),
            'config_valid': env_valid
        },
        'features': {
            'multi_model': True,
            'soc_analysis': True,
            'opensearch_integration': opensearch_status == 'connected',
            'session_continuity': True
        }
    }
    
    return jsonify(health_data)


@app.route('/security/analyze', methods=['POST'])
def security_analyze():
    """Analyze security alerts using security_analyzer module."""
    if not request.is_json:
        return jsonify({'error': 'JSON required'}), 400
    
    data = request.get_json()
    alert_data = data.get('alert_data')
    
    if not alert_data:
        return jsonify({'error': 'alert_data required'}), 400
    
    try:
        # Use the new ai_handler instead of old security_analyzer
        result = analyze_security_alert(alert_data)
        return jsonify({
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'alert_id': alert_data.get('alert_id', 'unknown'),
            'analysis': result.get('content', 'Analysis completed')
        })
    except Exception as e:
        logger.error(f"Security analysis failed: {e}")
        return jsonify({'error': 'Analysis failed', 'details': str(e)}), 500


@app.route('/security/alerts')
def get_alerts():
    """Get recent security alerts from database."""
    try:
        import alert_store
        alerts = alert_store.get_alerts(20)
        
        # Map to expected response format
        formatted_alerts = []
        for alert in alerts:
            formatted_alerts.append({
                'id': alert['id'],
                'timestamp': alert['timestamp'],
                'alert_data': alert['alert_data'],
                'analysis': alert['ai_response']
            })
        
        return jsonify({'alerts': formatted_alerts})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/opensearch/alert', methods=['POST', 'PUT', 'PATCH'])
def opensearch_webhook():
    """
    Simple webhook endpoint for alerts.
    Flow: Alert in → SQLite → AI analysis (with OSINT) → Update SQLite → Return OK
    """
    alert_id = None
    try:
        alert_json = request.get_json()
        if not alert_json:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        # Step 1: Save alert to SQLite (always succeeds)
        alert_id = save_alert(alert_json)
        logger.info(f"Alert saved with ID: {alert_id}")
        
        # Step 2: Try AI analysis with timeout
        try:
            # Add shorter timeout for AI analysis
            full_analysis = analyze_security_alert(alert_json, max_tokens=500, timeout=15)
            
            # Step 3: Update alert with complete analysis
            from alert_store import update_alert
            update_alert(alert_id, json.dumps(full_analysis))
            logger.info(f"Alert {alert_id} updated with AI analysis")
            
            return jsonify({
                "status": "processed", 
                "alert_id": alert_id,
                "analysis_complete": True
            }), 200
            
        except Exception as ai_error:
            # AI failed but alert is saved
            logger.error(f"AI analysis failed for alert {alert_id}: {ai_error}")
            return jsonify({
                "status": "saved", 
                "alert_id": alert_id,
                "analysis_complete": False,
                "error": f"AI analysis failed: {str(ai_error)}"
            }), 202  # 202 Accepted - request accepted but processing incomplete
        
    except Exception as e:
        logger.error(f"Alert webhook error: {e}")
        return jsonify({
            'error': str(e),
            'alert_id': alert_id
        }), 500


@app.route('/opensearch/alert/<int:alert_id>')
def get_opensearch_alert(alert_id):
    """Get a specific alert and its analysis"""
    try:
        alert = get_alert_by_id(alert_id)
        if alert:
            return jsonify(alert), 200
        else:
            return jsonify({'error': 'Alert not found'}), 404
            
    except Exception as e:
        logger.error(f"Error retrieving alert: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/opensearch/indices')
def opensearch_indices():
    """Get available OpenSearch indices."""
    try:
        indices = get_available_indices()
        return jsonify({
            'status': 'success',
            'indices_count': len(indices),
            'indices': indices,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to get indices: {e}")
        return jsonify({
            'error': 'Failed to retrieve indices',
            'details': str(e),
            'fallback_message': 'OpenSearch may not be configured'
        }), 500


@app.route('/opensearch/query', methods=['POST'])
def opensearch_query():
    """Execute OpenSearch query."""
    if not request.is_json:
        return jsonify({'error': 'JSON required'}), 400
    
    try:
        data = request.get_json()
        query = data.get('query')
        
        # Use provided query or default
        result = query_opensearch(query)
        
        return jsonify({
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'results': result
        })
    except Exception as e:
        logger.error(f"OpenSearch query failed: {e}")
        return jsonify({'error': 'Query failed', 'details': str(e)}), 500


@app.route('/opensearch/integration/status')
def opensearch_status():
    """OpenSearch integration status."""
    try:
        indices = get_available_indices()
        connected = len(indices) > 0
        
        return jsonify({
            'integration_enabled': True,
            'status': 'connected' if connected else 'disconnected',
            'indices_available': len(indices),
            'message': f'Found {len(indices)} indices' if connected else 'No connection',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'integration_enabled': False,
            'status': 'error',
            'message': str(e),
            'timestamp': datetime.now().isoformat()
        })


@app.route('/soc/analyze', methods=['POST'])
def soc_analyze():
    """SOC-specific analysis with OpenSearch integration."""
    if not request.is_json:
        return jsonify({'error': 'JSON required'}), 400
    
    try:
        data = request.get_json()
        incident_data = data.get('incident_data', '').strip()
        template = data.get('template', 'incident_analysis')
        
        if not incident_data:
            return jsonify({'error': 'incident_data required'}), 400
        
        if template not in SOC_TEMPLATES:
            return jsonify({'error': f'Invalid template. Valid: {list(SOC_TEMPLATES.keys())}'}), 400
        
        # Try to get OpenSearch data
        opensearch_data = None
        try:
            opensearch_query = data.get('opensearch_query')
            opensearch_data = query_opensearch(opensearch_query)
        except Exception as e:
            logger.warning(f"OpenSearch query failed: {e}")
        
        # Enhance incident data with OpenSearch results
        enhanced_data = incident_data
        if opensearch_data:
            enhanced_data = f"{incident_data}\n\nOpenSearch Data:\n{opensearch_data}"
        
        # Use ai_handler for analysis
        result = analyze_security_alert(enhanced_data, template)
        
        # Add SOC-specific metadata
        result.update({
            'template': template,
            'opensearch_used': opensearch_data is not None,
            'timestamp': datetime.now().isoformat()
        })
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"SOC analysis failed: {e}")
        return jsonify({'error': 'SOC analysis failed', 'details': str(e)}), 500


@app.route('/soc/templates')
def soc_templates():
    """Get available SOC analysis templates."""
    return jsonify({
        'templates': {
            name: {
                'description': config['prompt'],
                'required_fields': config['fields']
            }
            for name, config in SOC_TEMPLATES.items()
        },
        'count': len(SOC_TEMPLATES)
    })


# Error handlers
@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({'error': 'Not found', 'message': str(error)}), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"Internal error: {error}")
    return jsonify({'error': 'Internal server error'}), 500


# Helper functions for configuration and validation
def validate_startup():
    """Validate application startup configuration."""
    issues = []
    
    # Check AI client
    if not os.getenv('DEEPSEEK_API_KEY'):
        issues.append('DEEPSEEK_API_KEY not configured')
    
    # Check OpenSearch (optional)
    if not os.getenv('OPENSEARCH_HOST'):
        logger.info('OpenSearch not configured - text-only mode')
    
    return len(issues) == 0, issues


def log_startup_status():
    """Log application startup status."""
    valid, issues = validate_startup()
    
    if valid:
        logger.info("✅ All critical components validated")
    else:
        logger.warning("⚠️ Configuration issues detected:")
        for issue in issues:
            logger.warning(f"  - {issue}")


# Application startup
if __name__ == '__main__':
    # Validate configuration
    log_startup_status()
    
    # Get configuration
    host = os.getenv('FLASK_HOST', '127.0.0.1')
    port = int(os.getenv('FLASK_PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    
    logger.info(f"Starting SOC AI Chat on {host}:{port}")
    logger.info(f"Debug mode: {debug}")
    
    # Run Flask application
    app.run(
        host=host,
        port=port,
        debug=debug,
        threaded=True
    )