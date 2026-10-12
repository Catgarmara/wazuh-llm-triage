#!/usr/bin/env python3
"""
AI Handler - SOC-Aware AI Client Manager
TASK-010: Create ai_handler.py with SOC context

Provides three main functions:
- init_ai_client(provider='deepseek') - Initialize AI client (DeepSeek or Gemini)
- chat_completion(messages, session_id=None) - Handle chat with SOC context
- analyze_security_alert(alert_data, connector=None) - Analyze alerts with SOC expertise

Direct API calls with SOC context injection for security analysis.
"""

import os
import json
import logging
import time
import requests
import re
from typing import Dict, Any, List, Optional, Union
from datetime import datetime

# Import AI clients
from ai_clients import get_ai_client
from connectors.opensearch import query_opensearch, get_available_indices
from alert_store import save_alert

logger = logging.getLogger(__name__)

def _extract_opensearch_query(text):
    """
    Extract OpenSearch query from AI response text.
    Handles multi-line JSON properly by counting braces instead of using regex.
    
    Args:
        text (str): The AI response text containing [OPENSEARCH_QUERY: {...}]
        
    Returns:
        dict: Parsed JSON query object, or None if not found/invalid
    """
    start_marker = '[OPENSEARCH_QUERY:'
    end_marker = ']'
    
    start_pos = text.find(start_marker)
    if start_pos == -1:
        return None
    
    # Find the start of JSON (first '{' after the marker)
    json_start = text.find('{', start_pos)
    if json_start == -1:
        return None
    
    # Count braces to find the matching closing brace
    brace_count = 0
    json_end = -1
    
    for i in range(json_start, len(text)):
        char = text[i]
        if char == '{':
            brace_count += 1
        elif char == '}':
            brace_count -= 1
            if brace_count == 0:
                json_end = i + 1
                break
    
    if json_end == -1:
        return None
    
    # Check if there's a closing ] after the JSON (allowing whitespace)
    remaining = text[json_end:].lstrip()
    if not remaining.startswith(end_marker):
        return None
    
    # Extract and validate the JSON
    json_content = text[json_start:json_end]
    try:
        parsed = json.loads(json_content)
        return parsed
    except json.JSONDecodeError:
        return None

# Build SOC Context dynamically from environment
def _build_soc_context():
    """Build SOC context with available OpenSearch indices from environment"""
    base_context = """You are a senior SOC analyst with 10+ years of cybersecurity experience. 
Analyze security data for threats, IOCs, and provide actionable recommendations using industry frameworks like MITRE ATT&CK. 
Be thorough, methodical, and focus on protecting the organization."""
    
    # Try to get discovered field mappings from OpenSearch connector
    mapping_context = ""
    try:
        from connectors.opensearch import OpenSearchConnector
        connector = OpenSearchConnector()
        mapping_context = connector.get_mapping_context()
        if mapping_context and mapping_context != "No OpenSearch indices discovered.":
            # We have discovered mappings, use them
            opensearch_context = f"""

IMPORTANT: You have access to OpenSearch for querying security logs.

{mapping_context}

When users ask about security data:
1. Build an OpenSearch query JSON using the EXACT field names shown above
2. Indicate with: [OPENSEARCH_QUERY: <json>]
3. To use specific index: {{"_index": "index-name", "query": {{...}}}}
4. CRITICAL: Use the discovered field names, NOT generic field names

For example, if the IP field is called "remote" in the waf index, use "remote" not "source_ip"."""
            return base_context + opensearch_context
    except Exception as e:
        logger.debug(f"Could not get mapping context: {e}")
    
    # Fallback to simple index list if mapping discovery failed
    indices = []
    for key, value in os.environ.items():
        if key.startswith('OPENSEARCH_') and key.endswith('_INDEX'):
            index_name = key.replace('OPENSEARCH_', '').replace('_INDEX', '')
            indices.append(f"- {index_name}: {value}")
    
    if indices:
        opensearch_context = f"""

IMPORTANT: You have access to OpenSearch for querying security logs.
Available indices from configuration:
{chr(10).join(indices)}

When users ask about security data:
1. Build an OpenSearch query JSON 
2. Indicate with: [OPENSEARCH_QUERY: <json>]
3. To use specific index: {{"_index": "index-name", "query": {{...}}}}

Example: [OPENSEARCH_QUERY: {{"query": {{"term": {{"source_ip": "192.168.1.1"}}}}}}]"""
    else:
        opensearch_context = ""
    
    return base_context + opensearch_context

# SOC Context - built from environment
SOC_SYSTEM_CONTEXT = _build_soc_context()

# Global AI client instance
_ai_client = None
_current_provider = None


def init_ai_client(provider='deepseek', **kwargs):
    """
    Initialize AI client for the specified provider.
    
    Args:
        provider (str): AI provider ('deepseek' or 'gemini')
        **kwargs: Provider-specific configuration
        
    Returns:
        bool: True if initialization successful
        
    Raises:
        Exception: If initialization fails
    """
    global _ai_client, _current_provider
    
    try:
        logger.info(f"Initializing AI client for provider: {provider}")
        
        # Get API key from environment
        if provider.lower() == 'deepseek':
            api_key = os.getenv('DEEPSEEK_API_KEY')
            if not api_key:
                raise Exception("DEEPSEEK_API_KEY not found in environment")
            _ai_client = get_ai_client('deepseek', **kwargs)
        elif provider.lower() == 'gemini':
            api_key = os.getenv('GEMINI_API_KEY')
            if not api_key:
                raise Exception("GEMINI_API_KEY not found in environment")
            _ai_client = get_ai_client('gemini', **kwargs)
        else:
            raise Exception(f"Unsupported provider: {provider}")
        
        # Validate connection
        if _ai_client.validate_connection():
            _current_provider = provider
            logger.info(f"AI client initialized successfully: {provider}")
            return True
        else:
            raise Exception(f"Failed to validate connection to {provider}")
            
    except Exception as e:
        logger.error(f"Failed to initialize AI client: {e}")
        _ai_client = None
        _current_provider = None
        raise


def chat_completion(messages, session_id=None, include_soc_context=True, **kwargs):
    """Handle chat completion with SOC context injection and OpenSearch query detection"""
    if not _ai_client:
        raise Exception("AI client not initialized. Call init_ai_client() first.")
    
    start_time = time.time()
    
    # Prepare messages with SOC context if requested
    enhanced_messages = []
    if include_soc_context:
        enhanced_messages.append({"role": "system", "content": SOC_SYSTEM_CONTEXT})
    else:
        # Basic English prompt when not using SOC context
        enhanced_messages.append({"role": "system", "content": "You are a helpful AI assistant. Please respond in English."})
    enhanced_messages.extend(messages)
    
    # Generate initial response
    response = _ai_client.generate_response(enhanced_messages, **kwargs)
    
    # Check if AI wants to query OpenSearch
    if '[OPENSEARCH_QUERY:' in response.content:
        logger.info("AI requested OpenSearch query")
        
        # Extract query from response using robust JSON extraction
        query_json = _extract_opensearch_query(response.content)
        
        if query_json:
            try:
                logger.info(f"Executing AI-generated query: {json.dumps(query_json)[:200]}")
                
                # Execute OpenSearch query
                from connectors.opensearch import OpenSearchConnector
                connector = OpenSearchConnector()
                
                # Check if AI specified a specific index
                index = query_json.pop('_index', None)  # Remove _index from query
                
                # Use specified index or default from .env
                results = connector.query(query_json, index=index)
                
                # Format results for AI
                if results and results.get('hits', {}).get('hits'):
                    hits_count = results['hits']['total']['value']
                    hits_data = json.dumps(results['hits']['hits'][:10], indent=2)[:5000]  # Limit data
                    
                    # Create follow-up message with results
                    results_message = f"""OpenSearch query executed successfully.
Found {hits_count} total results. Here are the first 10:

{hits_data}

Please analyze these results and provide insights."""
                    
                    # Build combined response showing query and results
                    query_display = json.dumps(query_json, indent=2)
                    combined_response = f"""## Executing OpenSearch Query

```json
{query_display}
```
{f"Target index: {index}" if index else "Using default index"}

### Query Results
Found {hits_count} total results.

"""
                else:
                    results_message = "OpenSearch query returned no results."
                    
                    # Build combined response showing query but no results
                    query_display = json.dumps(query_json, indent=2)
                    combined_response = f"""## Executing OpenSearch Query

```json
{query_display}
```
{f"Target index: {index}" if index else "Using default index"}

### Query Results
No results found.

"""
                
                # Add results to conversation and get AI's analysis
                enhanced_messages.append({"role": "assistant", "content": response.content})
                enhanced_messages.append({"role": "user", "content": results_message})
                
                # Get AI's analysis of the results
                final_response = _ai_client.generate_response(enhanced_messages, **kwargs)
                
                # Combine the query display with AI's analysis
                response.content = combined_response + "### Analysis\n" + final_response.content
                
            except Exception as e:
                logger.error(f"OpenSearch query failed: {e}")
                error_msg = f"\n\n[Error: OpenSearch query failed: {e}]"
                response.content += error_msg
        else:
            logger.error("Failed to extract valid OpenSearch query from AI response")
            error_msg = f"\n\n[Error: Could not parse OpenSearch query from AI response]"
            response.content += error_msg
    
    return {
        "response": response.content,
        "provider": _current_provider,
        "model": response.model,
        "session_id": session_id,
        "response_time": time.time() - start_time,
        "timestamp": datetime.now().isoformat(),
        "soc_context_applied": include_soc_context
    }


def analyze_security_alert(alert_data, connector=None, **kwargs):
    """Analyze security alert with SOC expertise and OSINT enrichment"""
    if not _ai_client:
        raise Exception("AI client not initialized. Call init_ai_client() first.")
    
    start_time = time.time()
    
    # Phase 1: Initial analysis
    initial_prompt = _build_alert_analysis_prompt(alert_data, {"phase": "initial"})
    messages = [
        {"role": "system", "content": SOC_SYSTEM_CONTEXT},
        {"role": "user", "content": initial_prompt}
    ]
    initial_response = _ai_client.generate_response(messages, **kwargs)
    initial_analysis = initial_response.content
    
    # Extract IoCs from initial analysis
    iocs = _extract_iocs(initial_analysis)
    ioc_strings = []
    for ioc in iocs:
        if ioc.get('value'):
            ioc_strings.append(ioc['value'])
    
    # Phase 2: OSINT enrichment
    osint_data = "No OSINT data available"
    if ioc_strings:
        osint_query = f"Security threat intelligence for: {' '.join(ioc_strings[:5])}"  # Limit to 5 IoCs
        osint_data = get_osint_data(osint_query)
    
    # Phase 3: Final analysis with OSINT context
    final_prompt = f"""Based on your initial analysis and OSINT intelligence, provide final security assessment:

ALERT DATA:
{json.dumps(alert_data, indent=2) if isinstance(alert_data, dict) else alert_data}

INITIAL ANALYSIS:
{initial_analysis}

OSINT INTELLIGENCE:
{osint_data}

Provide:
1. Executive Summary
2. Threat Assessment (severity 1-10)
3. Attack Attribution (if possible)
4. Recommended Actions
5. Detection Rules to implement"""
    
    final_messages = [
        {"role": "system", "content": SOC_SYSTEM_CONTEXT},
        {"role": "user", "content": final_prompt}
    ]
    final_response = _ai_client.generate_response(final_messages, **kwargs)
    
    # Build comprehensive result
    analysis_result = {
        "alert_id": alert_data.get('id', f"alert_{int(time.time())}"),
        "initial_analysis": initial_analysis,
        "iocs": iocs,
        "osint": osint_data,
        "final_analysis": final_response.content,
        "content": final_response.content,  # Backward compatibility
        "risk_level": _extract_risk_level(final_response.content),
        "recommendations": _extract_recommendations(final_response.content),
        "provider": _current_provider,
        "model": final_response.model,
        "analysis_time": time.time() - start_time,
        "timestamp": datetime.now().isoformat()
    }
    
    # Note: Removed save_alert - let webhook handle storage
    
    return analysis_result


def _build_alert_analysis_prompt(alert_data, context):
    """Build the prompt for alert analysis"""
    return f"""Analyze this security alert with your SOC expertise:

ALERT DATA: {alert_data}

Please provide:
1. Risk Level (Critical/High/Medium/Low) with justification
2. Threat Assessment and IOCs
3. Immediate Response Actions
4. Investigation Steps

Format your response clearly."""


def _extract_risk_level(analysis_text):
    """Extract risk level from analysis text"""
    analysis_lower = analysis_text.lower()
    for level in ["critical", "high", "medium", "low"]:
        if level in analysis_lower:
            return level.title()
    return "Unknown"


def _extract_iocs(analysis_text):
    """Extract IOCs from analysis text - simplified"""
    import re
    iocs = []
    # IP addresses
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', analysis_text)
    iocs.extend([{"type": "ip", "value": ip} for ip in ips[:5]])
    return iocs


def _extract_recommendations(analysis_text):
    """Extract recommendations from analysis text"""
    recommendations = []
    for line in analysis_text.split('\n'):
        line = line.strip()
        if line.startswith(('-', '*', '1.', '2.', '3.')) and len(recommendations) < 5:
            recommendations.append(line)
    return recommendations


def get_current_provider():
    """
    Get the currently active AI provider.
    
    Returns:
        str: Current provider name ('deepseek', 'gemini', etc.) or None if not initialized
    """
    global _current_provider
    return _current_provider


# Convenience function for getting current client status
def get_osint_data(query_text):
    """
    Get OSINT data from Perplexity API for threat intelligence.
    
    Args:
        query_text: What to research (IPs, domains, CVEs, etc.)
        
    Returns:
        OSINT intelligence text or error message
    """
    try:
        perplexity_key = os.getenv('PERPLEXITY_API_KEY')
        if not perplexity_key:
            return "Perplexity API key not configured"
        
        response = requests.post(
            'https://api.perplexity.ai/chat/completions',
            headers={
                'Authorization': f'Bearer {perplexity_key}',
                'Content-Type': 'application/json'
            },
            json={
                'model': 'sonar',
                'messages': [
                    {
                        'role': 'user',
                        'content': f'Security research: {query_text}'
                    }
                ],
                'search_recency_filter': 'month'  # Get recent threat intel
            },
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            return data.get('choices', [{}])[0].get('message', {}).get('content', 'No OSINT data available')
        else:
            return f"Perplexity API error: {response.status_code}"
            
    except Exception as e:
        logger.error(f"OSINT lookup failed: {e}")
        return f"OSINT error: {str(e)}"


def get_client_status():
    """Get current AI client status and configuration"""
    return {
        "initialized": _ai_client is not None,
        "provider": _current_provider,
        "model": _ai_client._get_model_name() if _ai_client else None,
        "validated": _ai_client.is_validated if _ai_client else False
    }


if __name__ == "__main__":
    """Simple test of ai_handler functions"""
    print("Testing ai_handler.py...")
    try:
        print("1. Testing AI client initialization...")
        if init_ai_client('deepseek'):
            print("✅ AI client initialized successfully")
            
            print("2. Testing chat completion...")
            test_messages = [{"role": "user", "content": "What are common SOC alert types?"}]
            response = chat_completion(test_messages)
            print(f"✅ Chat response: {len(response['content'])} characters")
            
            print("3. Testing security alert analysis...")
            test_alert = {"id": "TEST_001", "event_type": "suspicious_login", "source_ip": "192.168.1.100"}
            analysis = analyze_security_alert(test_alert)
            print(f"✅ Alert analysis completed - Risk: {analysis['risk_level']}")
        else:
            print("❌ AI client initialization failed")
    except Exception as e:
        print(f"❌ Test failed: {e}")