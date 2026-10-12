#!/usr/bin/env python3
"""
Session Manager for Chat Application

Handles session-based conversation memory with thread-safe operations.
Extracted from app.py to improve code organization and modularity.

Features:
- Thread-safe session operations using RLock
- Automatic session expiration (24 hours)
- Message history limiting (10 messages) to prevent token overflow
- Model tracking for conversation continuity
- SOC metadata support for security operations
"""

import uuid
import threading
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple

# Configure logging
logger = logging.getLogger(__name__)

# Configuration constants
MAX_HISTORY_MESSAGES = 10
SESSION_TIMEOUT_HOURS = 24

# Thread-safe session storage
conversation_sessions = {}
session_lock = threading.RLock()


def get_or_create_session(session_id=None, default_model='deepseek'):
    """
    Get existing session or create a new one with model tracking.
    
    Args:
        session_id (str, optional): Existing session ID
        default_model (str, optional): Default model for new sessions
        
    Returns:
        tuple: (session_id, session_data)
    """
    with session_lock:
        if session_id and session_id in conversation_sessions:
            session_data = conversation_sessions[session_id]
            # Check if session is expired
            if datetime.now() - session_data['created_at'] > timedelta(hours=SESSION_TIMEOUT_HOURS):
                logger.info(f"Session {session_id} expired, creating new session")
                del conversation_sessions[session_id]
                session_id = None
            else:
                # Update last accessed time
                session_data['last_accessed'] = datetime.now()
                
                # Ensure backward compatibility - add missing fields if needed
                if 'selectedModel' not in session_data:
                    session_data['selectedModel'] = default_model
                    logger.info(f"Added selectedModel to existing session {session_id}: {default_model}")
                
                if 'modelHistory' not in session_data:
                    session_data['modelHistory'] = []
                    logger.info(f"Added modelHistory to existing session {session_id}")
                
                return session_id, session_data
        
        # Create new session with model tracking
        new_session_id = str(uuid.uuid4())
        conversation_sessions[new_session_id] = {
            'messages': [],
            'selectedModel': default_model,
            'modelHistory': [],
            'created_at': datetime.now(),
            'last_accessed': datetime.now()
        }
        logger.info(f"Created new conversation session: {new_session_id} with model: {default_model}")
        return new_session_id, conversation_sessions[new_session_id]


def add_message(session_id, role, content, metadata=None, model=None, provider=None):
    """
    Add a message to the session conversation history with optional SOC metadata and model tracking.
    
    Args:
        session_id (str): Session ID
        role (str): Message role ('user' or 'assistant')
        content (str): Message content
        metadata (dict, optional): SOC metadata including alert_id, severity, investigation_context
        model (str, optional): Model used to generate the message (for assistant messages)
        provider (str, optional): Provider used to generate the message (for assistant messages)
    """
    with session_lock:
        if session_id in conversation_sessions:
            session_data = conversation_sessions[session_id]
            message_data = {
                'role': role,
                'content': content,
                'timestamp': datetime.now()
            }
            
            # Add model tracking information for assistant messages
            if role == 'assistant' and model:
                message_data['model'] = model
                message_data['provider'] = provider or 'unknown'
                
                # Track model usage in modelHistory
                current_time = datetime.now()
                model_entry = {
                    'model': model,
                    'provider': provider or 'unknown',
                    'timestamp': current_time,
                    'message_count': 1
                }
                
                # Update or add to modelHistory
                existing_entry = None
                for entry in session_data.get('modelHistory', []):
                    if entry['model'] == model and entry['provider'] == (provider or 'unknown'):
                        existing_entry = entry
                        break
                
                if existing_entry:
                    existing_entry['message_count'] += 1
                    existing_entry['last_used'] = current_time
                else:
                    model_entry['first_used'] = current_time
                    model_entry['last_used'] = current_time
                    session_data.setdefault('modelHistory', []).append(model_entry)
            
            # Add SOC metadata if provided
            if metadata:
                message_data['soc_metadata'] = {
                    'alert_id': metadata.get('alert_id'),
                    'severity': metadata.get('severity'),
                    'investigation_context': metadata.get('investigation_context'),
                    'incident_type': metadata.get('incident_type'),
                    'analyst_id': metadata.get('analyst_id'),
                    'case_id': metadata.get('case_id'),
                    'source_system': metadata.get('source_system'),
                    'correlation_id': metadata.get('correlation_id')
                }
            
            session_data['messages'].append(message_data)
            
            # Limit history to prevent token overflow
            if len(session_data['messages']) > MAX_HISTORY_MESSAGES:
                # Remove oldest messages but keep the conversation balanced
                messages_to_remove = len(session_data['messages']) - MAX_HISTORY_MESSAGES
                if messages_to_remove % 2 == 1:
                    messages_to_remove += 1  # Remove even number to keep pairs
                
                session_data['messages'] = session_data['messages'][messages_to_remove:]
                logger.info(f"Trimmed session {session_id} history, removed {messages_to_remove} messages")
            
            session_data['last_accessed'] = datetime.now()


def get_history(session_id):
    """
    Get conversation history for a session.
    
    Args:
        session_id (str): Session ID
        
    Returns:
        list: List of messages formatted for API (role and content only)
    """
    with session_lock:
        if session_id in conversation_sessions:
            session_data = conversation_sessions[session_id]
            messages = []
            
            # Convert stored messages to API format
            for msg in session_data['messages']:
                messages.append({
                    'role': msg['role'],
                    'content': msg['content']
                })
            
            return messages
        
        return []


def cleanup_expired():
    """
    Clean up expired sessions to prevent memory leaks.
    Called periodically to maintain session hygiene.
    """
    with session_lock:
        current_time = datetime.now()
        expired_sessions = []
        
        for session_id, session_data in conversation_sessions.items():
            if current_time - session_data['last_accessed'] > timedelta(hours=SESSION_TIMEOUT_HOURS):
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            # Log cleanup details for model tracking
            session_data = conversation_sessions[session_id]
            model_info = {
                'selectedModel': session_data.get('selectedModel', 'unknown'),
                'modelHistory': len(session_data.get('modelHistory', [])),
                'messageCount': len(session_data.get('messages', []))
            }
            logger.info(f"Cleaning up expired session {session_id}: {model_info}")
            
            del conversation_sessions[session_id]
        
        if expired_sessions:
            logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")


def get_session_stats():
    """
    Get statistics about current sessions.
    
    Returns:
        dict: Session statistics including counts and model usage
    """
    with session_lock:
        stats = {
            'total_sessions': len(conversation_sessions),
            'models_in_use': {},
            'total_messages': 0
        }
        
        for session_data in conversation_sessions.values():
            selected_model = session_data.get('selectedModel', 'unknown')
            stats['models_in_use'][selected_model] = stats['models_in_use'].get(selected_model, 0) + 1
            stats['total_messages'] += len(session_data.get('messages', []))
        
        return stats


def update_session_model(session_id, model_name, validate_model_callback=None, record_model_switch_callback=None):
    """
    Update the selected model for a session with continuity management.
    
    Args:
        session_id (str): Session ID
        model_name (str): New model to select
        validate_model_callback (callable, optional): Function to validate model availability
        record_model_switch_callback (callable, optional): Function to record model switches
        
    Returns:
        bool: True if model was updated successfully, False otherwise
    """
    with session_lock:
        if session_id not in conversation_sessions:
            logger.warning(f"Attempted to update model for non-existent session: {session_id}")
            return False
        
        session_data = conversation_sessions[session_id]
        previous_model = session_data.get('selectedModel', 'deepseek')
        
        # Validate the new model is available (if callback provided)
        if validate_model_callback:
            client, actual_model, provider = validate_model_callback(model_name)
            if not client:
                logger.warning(f"Model {model_name} is not available, keeping {previous_model}")
                return False
        
        # Update session model - use the requested name, not the normalized one
        session_data['selectedModel'] = model_name
        session_data['last_accessed'] = datetime.now()
        
        # Log model switch for conversation continuity
        if previous_model != model_name:
            logger.info(f"Session {session_id} model switch: {previous_model} -> {model_name}")
            
            # Record model switch in monitoring system (if callback provided)
            if record_model_switch_callback:
                record_model_switch_callback(
                    from_model=previous_model,
                    to_model=model_name,
                    reason="user_selection",
                    user_id=session_id,
                    session_id=session_id
                )
            
            # Add a system message to maintain conversation context about the model switch
            context_message = f"[System: Model switched from {previous_model} to {model_name}. Conversation context maintained.]"
            session_data['messages'].append({
                'role': 'system',
                'content': context_message,
                'timestamp': datetime.now(),
                'model_switch': True,
                'previous_model': previous_model,
                'new_model': model_name
            })
        
        return True


def get_session_model(session_id):
    """
    Get the currently selected model for a session.
    
    Args:
        session_id (str): Session ID
        
    Returns:
        str: Currently selected model name, or None if session doesn't exist
    """
    with session_lock:
        if session_id in conversation_sessions:
            return conversation_sessions[session_id].get('selectedModel', 'deepseek')
        return None