#!/usr/bin/env python3
"""
Simple AI Clients for DeepSeek and Google Gemini.
No enterprise bullshit, just basic functionality.
"""

import os
import logging
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class AIProvider(Enum):
    """Supported AI providers."""
    DEEPSEEK = "deepseek"
    GEMINI = "gemini"


@dataclass
class AIResponse:
    """Simple response object from AI."""
    content: str
    model: str
    provider: AIProvider
    response_time: float = 0.0
    usage: Optional[Dict[str, Any]] = None


class DeepSeekClient:
    """Simple DeepSeek client using OpenAI-compatible API."""
    
    def __init__(self, api_key: str = None):
        """Initialize DeepSeek client."""
        self.api_key = api_key or os.getenv('DEEPSEEK_API_KEY')
        if not self.api_key:
            raise ValueError("DeepSeek API key required")
        
        self.provider = AIProvider.DEEPSEEK
        self._client = None
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize the OpenAI client for DeepSeek."""
        try:
            from openai import OpenAI
            self._client = OpenAI(
                api_key=self.api_key,
                base_url=os.getenv('DEEPSEEK_BASE_URL', 'https://api.deepseek.com')
            )
            logger.info("DeepSeek client initialized")
        except Exception as e:
            logger.error(f"Failed to initialize DeepSeek client: {e}")
            raise
    
    def generate_response(
        self, 
        messages: List[Dict[str, str]], 
        model: str = "deepseek-chat",
        temperature: float = 0.7,
        max_tokens: int = 1000,
        **kwargs
    ) -> AIResponse:
        """Generate a response from DeepSeek."""
        if not self._client:
            raise RuntimeError("DeepSeek client not initialized")
        
        start_time = time.time()
        
        try:
            response = self._client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=kwargs.get('timeout', 30)
            )
            
            content = response.choices[0].message.content
            response_time = time.time() - start_time
            
            # Extract usage if available
            usage = None
            if hasattr(response, 'usage') and response.usage:
                usage = {
                    'prompt_tokens': response.usage.prompt_tokens,
                    'completion_tokens': response.usage.completion_tokens,
                    'total_tokens': response.usage.total_tokens
                }
            
            return AIResponse(
                content=content,
                model=model,
                provider=AIProvider.DEEPSEEK,
                response_time=response_time,
                usage=usage
            )
            
        except Exception as e:
            logger.error(f"DeepSeek API error: {e}")
            raise
    
    def validate_connection(self) -> bool:
        """Test if the client can connect to DeepSeek."""
        try:
            test_messages = [{"role": "user", "content": "test"}]
            response = self.generate_response(test_messages, max_tokens=1)
            return bool(response.content)
        except Exception as e:
            logger.error(f"DeepSeek validation failed: {e}")
            return False


class GeminiClient:
    """Simple Google Gemini client."""
    
    def __init__(self, api_key: str = None):
        """Initialize Gemini client."""
        self.api_key = api_key or os.getenv('GEMINI_API_KEY')
        if not self.api_key:
            raise ValueError("Gemini API key required")
        
        self.provider = AIProvider.GEMINI
        self._client = None
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize the Gemini client."""
        try:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            
            # Configure safety settings to be permissive
            from google.generativeai.types import HarmCategory, HarmBlockThreshold
            self.safety_settings = [
                {"category": HarmCategory.HARM_CATEGORY_HARASSMENT, "threshold": HarmBlockThreshold.BLOCK_NONE},
                {"category": HarmCategory.HARM_CATEGORY_HATE_SPEECH, "threshold": HarmBlockThreshold.BLOCK_NONE},
                {"category": HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT, "threshold": HarmBlockThreshold.BLOCK_NONE},
                {"category": HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT, "threshold": HarmBlockThreshold.BLOCK_NONE}
            ]
            
            self._client = genai.GenerativeModel(
                model_name='gemini-1.5-flash',
                safety_settings=self.safety_settings
            )
            logger.info("Gemini client initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Gemini client: {e}")
            raise
    
    def generate_response(
        self, 
        messages: List[Dict[str, str]], 
        temperature: float = 0.7,
        max_tokens: int = 1000,
        **kwargs
    ) -> AIResponse:
        """Generate a response from Gemini."""
        if not self._client:
            raise RuntimeError("Gemini client not initialized")
        
        start_time = time.time()
        
        try:
            # Convert messages to Gemini format
            prompt = self._format_messages_for_gemini(messages)
            
            # Configure generation parameters
            generation_config = {
                'temperature': temperature,
                'max_output_tokens': max_tokens,
                'candidate_count': 1
            }
            
            response = self._client.generate_content(
                contents=prompt,
                generation_config=generation_config,
                safety_settings=self.safety_settings
            )
            
            content = response.text
            response_time = time.time() - start_time
            
            # Extract usage if available
            usage = None
            if hasattr(response, 'usage_metadata'):
                usage = {
                    'prompt_tokens': getattr(response.usage_metadata, 'prompt_token_count', 0),
                    'completion_tokens': getattr(response.usage_metadata, 'candidates_token_count', 0),
                    'total_tokens': getattr(response.usage_metadata, 'total_token_count', 0)
                }
            
            return AIResponse(
                content=content,
                model='gemini-1.5-flash',
                provider=AIProvider.GEMINI,
                response_time=response_time,
                usage=usage
            )
            
        except Exception as e:
            logger.error(f"Gemini API error: {e}")
            raise
    
    def _format_messages_for_gemini(self, messages: List[Dict[str, str]]) -> str:
        """Convert OpenAI-style messages to Gemini format."""
        formatted_parts = []
        
        for message in messages:
            role = message.get('role', 'user')
            content = message.get('content', '')
            
            if role == 'system':
                formatted_parts.append(f"System: {content}")
            elif role == 'assistant':
                formatted_parts.append(f"Assistant: {content}")
            else:
                formatted_parts.append(f"User: {content}")
        
        return "\n\n".join(formatted_parts)
    
    def validate_connection(self) -> bool:
        """Test if the client can connect to Gemini."""
        try:
            test_messages = [{"role": "user", "content": "test"}]
            response = self.generate_response(test_messages, max_tokens=1)
            return bool(response.content)
        except Exception as e:
            logger.error(f"Gemini validation failed: {e}")
            return False


def get_ai_client(provider: str = 'deepseek', **kwargs):
    """
    Simple factory to get an AI client.
    
    Args:
        provider: 'deepseek' or 'gemini'
        **kwargs: Additional parameters for the client
    
    Returns:
        AI client instance
    """
    provider = provider.lower()
    
    if provider == 'deepseek':
        return DeepSeekClient(**kwargs)
    elif provider == 'gemini':
        return GeminiClient(**kwargs)
    else:
        raise ValueError(f"Unknown provider: {provider}")


def validate_all_providers() -> Dict[str, bool]:
    """Test all configured providers."""
    results = {}
    
    # Test DeepSeek
    if os.getenv('DEEPSEEK_API_KEY'):
        try:
            client = DeepSeekClient()
            results['deepseek'] = client.validate_connection()
        except Exception as e:
            logger.error(f"DeepSeek validation error: {e}")
            results['deepseek'] = False
    
    # Test Gemini
    if os.getenv('GEMINI_API_KEY'):
        try:
            client = GeminiClient()
            results['gemini'] = client.validate_connection()
        except Exception as e:
            logger.error(f"Gemini validation error: {e}")
            results['gemini'] = False
    
    return results


# For backward compatibility
AIClientFactory = type('AIClientFactory', (), {
    'get_client': staticmethod(get_ai_client)
})