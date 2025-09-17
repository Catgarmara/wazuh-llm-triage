#!/usr/bin/env python3
"""
AI Clients module for multi-provider support in Flask chat application.

This module provides:
- Abstract base class for AI client implementations
- Factory pattern for client instantiation
- Unified interface for different AI providers (DeepSeek, Google Gemini)
- Environment variable validation and configuration management
- Error handling and provider-specific optimizations

Supported providers:
- DeepSeek (via OpenAI-compatible API)
- Google Gemini (via Google Generative AI SDK)
"""

import os
import logging
import threading
import hashlib
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Iterator, List, Union
from dataclasses import dataclass
from enum import Enum
import time
from datetime import datetime, timedelta
from collections import defaultdict, deque
import weakref
# from core.performance_cache import (
#     performance_cache, connection_pool, CacheType,
#     cached_model_metadata, cache_model_metadata,
#     cached_validation_result, cache_validation_result,
#     cached_connection_status, cache_connection_status
# )

# Configure logging
logger = logging.getLogger(__name__)

# Import error recovery components (will be initialized later to avoid circular imports)
# try:
#     from core.error_recovery import get_error_recovery, ErrorRecoveryOrchestrator
#     RECOVERY_AVAILABLE = True
#     logger.info("Error recovery module available")
# except ImportError:
RECOVERY_AVAILABLE = False
logger.info("Error recovery module disabled for simplification")


class AIProvider(Enum):
    """Supported AI provider types."""
    DEEPSEEK = "deepseek"
    GEMINI = "gemini"


@dataclass
class PerformanceMetrics:
    """Performance metrics for AI client operations."""
    provider: AIProvider
    model: str
    operation_type: str  # 'generate_response' or 'generate_response_stream'
    response_time: float
    request_timestamp: datetime
    success: bool
    error_type: Optional[str] = None
    token_count: Optional[int] = None
    tokens_per_second: Optional[float] = None
    first_token_time: Optional[float] = None
    stream_chunk_count: Optional[int] = None


class PerformanceMonitor:
    """Global performance monitoring and metrics collection for AI clients."""
    
    def __init__(self, max_metrics_history: int = 1000):
        self._metrics_history: deque = deque(maxlen=max_metrics_history)
        self._metrics_by_provider: Dict[AIProvider, deque] = defaultdict(lambda: deque(maxlen=100))
        self._metrics_by_model: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self._lock = threading.RLock()
        self._start_time = datetime.now()
        
        # Performance thresholds
        self.response_time_warning_threshold = 10.0  # seconds
        self.response_time_critical_threshold = 30.0  # seconds
        self.tokens_per_second_threshold = 10.0  # minimum acceptable rate
    
    def record_metrics(self, metrics: PerformanceMetrics):
        """Record performance metrics for analysis."""
        with self._lock:
            self._metrics_history.append(metrics)
            self._metrics_by_provider[metrics.provider].append(metrics)
            self._metrics_by_model[metrics.model].append(metrics)
            
            # Log performance warnings
            if metrics.response_time > self.response_time_critical_threshold:
                logger.warning(f"Critical performance: {metrics.provider.value}/{metrics.model} "
                             f"took {metrics.response_time:.2f}s (>{self.response_time_critical_threshold}s)")
            elif metrics.response_time > self.response_time_warning_threshold:
                logger.warning(f"Slow performance: {metrics.provider.value}/{metrics.model} "
                             f"took {metrics.response_time:.2f}s (>{self.response_time_warning_threshold}s)")
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary."""
        with self._lock:
            if not self._metrics_history:
                return {
                    'total_requests': 0,
                    'uptime_seconds': (datetime.now() - self._start_time).total_seconds(),
                    'providers': {},
                    'models': {}
                }
            
            total_requests = len(self._metrics_history)
            successful_requests = sum(1 for m in self._metrics_history if m.success)
            
            # Calculate overall statistics
            response_times = [m.response_time for m in self._metrics_history if m.success]
            avg_response_time = sum(response_times) / len(response_times) if response_times else 0
            
            # Calculate provider-specific statistics
            provider_stats = {}
            for provider, metrics in self._metrics_by_provider.items():
                if metrics:
                    provider_response_times = [m.response_time for m in metrics if m.success]
                    provider_stats[provider.value] = {
                        'total_requests': len(metrics),
                        'successful_requests': sum(1 for m in metrics if m.success),
                        'success_rate': sum(1 for m in metrics if m.success) / len(metrics),
                        'avg_response_time': sum(provider_response_times) / len(provider_response_times) if provider_response_times else 0,
                        'min_response_time': min(provider_response_times) if provider_response_times else 0,
                        'max_response_time': max(provider_response_times) if provider_response_times else 0
                    }
            
            # Calculate model-specific statistics
            model_stats = {}
            for model, metrics in self._metrics_by_model.items():
                if metrics:
                    model_response_times = [m.response_time for m in metrics if m.success]
                    tokens_per_sec = [m.tokens_per_second for m in metrics if m.success and m.tokens_per_second]
                    model_stats[model] = {
                        'total_requests': len(metrics),
                        'successful_requests': sum(1 for m in metrics if m.success),
                        'success_rate': sum(1 for m in metrics if m.success) / len(metrics),
                        'avg_response_time': sum(model_response_times) / len(model_response_times) if model_response_times else 0,
                        'avg_tokens_per_second': sum(tokens_per_sec) / len(tokens_per_sec) if tokens_per_sec else 0
                    }
            
            return {
                'total_requests': total_requests,
                'successful_requests': successful_requests,
                'success_rate': successful_requests / total_requests if total_requests > 0 else 0,
                'avg_response_time': avg_response_time,
                'uptime_seconds': (datetime.now() - self._start_time).total_seconds(),
                'providers': provider_stats,
                'models': model_stats,
                'performance_thresholds': {
                    'warning_threshold': self.response_time_warning_threshold,
                    'critical_threshold': self.response_time_critical_threshold,
                    'min_tokens_per_second': self.tokens_per_second_threshold
                }
            }
    
    def get_recent_metrics(self, minutes: int = 5) -> List[PerformanceMetrics]:
        """Get metrics from the last N minutes."""
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        with self._lock:
            return [m for m in self._metrics_history if m.request_timestamp >= cutoff_time]
    
    def clear_metrics(self):
        """Clear all stored metrics (for testing/cleanup)."""
        with self._lock:
            self._metrics_history.clear()
            self._metrics_by_provider.clear()
            self._metrics_by_model.clear()
            self._start_time = datetime.now()


# Global performance monitor instance
performance_monitor = PerformanceMonitor()


@dataclass
class ModelInfo:
    """Information about an AI model."""
    name: str
    provider: AIProvider
    max_tokens: int
    supports_streaming: bool
    context_window: int
    description: Optional[str] = None


@dataclass
class AIResponse:
    """Standardized response from AI providers."""
    content: str
    model: str
    provider: AIProvider
    usage: Optional[Dict[str, int]] = None
    response_time: Optional[float] = None
    finish_reason: Optional[str] = None
    # Performance metrics
    request_timestamp: Optional[datetime] = None
    response_timestamp: Optional[datetime] = None
    stream_chunk_count: Optional[int] = None
    first_token_time: Optional[float] = None
    total_tokens_per_second: Optional[float] = None


class AIClientError(Exception):
    """Base exception for AI client errors."""
    pass


class AuthenticationError(AIClientError):
    """Authentication/API key related errors."""
    pass


class ConfigurationError(AIClientError):
    """Configuration and setup related errors."""
    pass


class APIError(AIClientError):
    """API call related errors."""
    pass


class TimeoutError(APIError):
    """Request timeout related errors."""
    pass


class BaseAIClient(ABC):
    """
    Abstract base class for AI clients providing unified interface.
    
    This class defines the contract that all AI provider implementations must follow,
    ensuring consistent behavior across different providers (DeepSeek, Gemini, etc.).
    """
    
    def __init__(self, api_key: str, **kwargs):
        """
        Initialize AI client with API key and provider-specific configuration.
        
        Args:
            api_key (str): API key for the provider
            **kwargs: Provider-specific configuration options
        """
        if not api_key or not api_key.strip():
            raise AuthenticationError("API key is required and cannot be empty")
        
        self.api_key = api_key.strip()
        self.config = kwargs
        self._validated = False
        
        # Performance monitoring configuration
        self.default_timeout = kwargs.get('default_timeout', 30)  # 30 second default
        self.enable_performance_monitoring = kwargs.get('enable_performance_monitoring', True)
        self._request_count = 0
        self._lock = threading.RLock()
        
        # Caching and connection pooling
        self._api_key_hash = self._hash_api_key(api_key)
        self._provider_key = f"{self.provider.value}_{self._api_key_hash}"
        self.enable_caching = kwargs.get('enable_caching', True)
        
    def _hash_api_key(self, api_key: str) -> str:
        """Create a hash of the API key for caching purposes."""
        return hashlib.sha256(api_key.encode()).hexdigest()[:16]
    
    @abstractmethod
    def generate_response(
        self, 
        messages: List[Dict[str, str]], 
        **kwargs
    ) -> AIResponse:
        """
        Generate a complete response from the AI provider.
        
        Args:
            messages (List[Dict[str, str]]): List of conversation messages
                Format: [{"role": "user|assistant|system", "content": "message"}]
            **kwargs: Provider-specific parameters (temperature, max_tokens, etc.)
        
        Returns:
            AIResponse: Standardized response object
            
        Raises:
            AuthenticationError: Invalid API key or authentication failure
            APIError: API call failure
            ConfigurationError: Invalid configuration or parameters
        """
        pass
    
    @abstractmethod
    def generate_response_stream(
        self, 
        messages: List[Dict[str, str]], 
        **kwargs
    ) -> Iterator[str]:
        """
        Generate a streaming response from the AI provider.
        
        Args:
            messages (List[Dict[str, str]]): List of conversation messages
            **kwargs: Provider-specific parameters
        
        Yields:
            str: Response content chunks as they arrive
            
        Raises:
            AuthenticationError: Invalid API key or authentication failure
            APIError: API call failure
            ConfigurationError: Invalid configuration or parameters
        """
        pass
    
    def validate_connection(self) -> bool:
        """
        Validate the connection and authentication with the AI provider.
        
        Returns:
            bool: True if connection is valid, False otherwise
            
        Raises:
            AuthenticationError: Invalid API key
            ConfigurationError: Invalid configuration
        """
        # Check cache first (caching disabled - performance_cache module not available)
        # if self.enable_caching:
        #     cached_result = cached_validation_result(self.provider.value, self._api_key_hash)
        #     if cached_result is not None:
        #         logger.debug(f"Using cached validation result for {self.provider.value}: {cached_result}")
        #         if cached_result:
        #             self._mark_validated()
        #         return cached_result
        
        # Perform actual validation
        is_valid = self._perform_validation()
        
        # Cache the result (caching disabled - performance_cache module not available)
        # if self.enable_caching:
        #     cache_validation_result(self.provider.value, self._api_key_hash, is_valid)
        
        if is_valid:
            self._mark_validated()
        
        return is_valid
    
    @abstractmethod
    def _perform_validation(self) -> bool:
        """
        Perform actual validation (to be implemented by subclasses).
        
        Returns:
            bool: True if connection is valid, False otherwise
        """
        pass
    
    def get_model_info(self) -> ModelInfo:
        """
        Get information about the current model configuration.
        
        Returns:
            ModelInfo: Model information including capabilities and limits
        """
        # Check cache first (caching disabled - performance_cache module not available)
        # if self.enable_caching:
        #     cached_info = cached_model_metadata(self.provider.value, self._get_model_name())
        #     if cached_info:
        #         logger.debug(f"Using cached model info for {self.provider.value}/{self._get_model_name()}")
        #         return ModelInfo(**cached_info)
        
        # Get fresh model info
        model_info = self._get_fresh_model_info()
        
        # Cache the result (caching disabled - performance_cache module not available)
        # if self.enable_caching:
        #     cache_model_metadata(
        #         self.provider.value, 
        #         self._get_model_name(),
        #         {
        #             'name': model_info.name,
        #             'provider': model_info.provider.value,
        #             'max_tokens': model_info.max_tokens,
        #             'supports_streaming': model_info.supports_streaming,
        #             'context_window': model_info.context_window,
        #             'description': model_info.description
        #         }
        #     )
        
        return model_info
    
    @abstractmethod
    def _get_fresh_model_info(self) -> ModelInfo:
        """
        Get fresh model information (to be implemented by subclasses).
        
        Returns:
            ModelInfo: Model information
        """
        pass
    
    @abstractmethod
    def _get_model_name(self) -> str:
        """
        Get the current model name (to be implemented by subclasses).
        
        Returns:
            str: Model name
        """
        pass
    
    @property
    @abstractmethod
    def provider(self) -> AIProvider:
        """
        Get the provider type for this client.
        
        Returns:
            AIProvider: The provider type enum
        """
        pass
    
    @property
    def is_validated(self) -> bool:
        """Check if the client has been validated."""
        return self._validated
    
    def _mark_validated(self):
        """Mark the client as validated (for internal use)."""
        self._validated = True
    
    def _record_performance_metrics(self, 
                                  operation_type: str, 
                                  start_time: float, 
                                  end_time: float, 
                                  success: bool, 
                                  model: str,
                                  error_type: Optional[str] = None,
                                  token_count: Optional[int] = None,
                                  first_token_time: Optional[float] = None,
                                  stream_chunk_count: Optional[int] = None):
        """Record performance metrics for monitoring."""
        if not self.enable_performance_monitoring:
            return
            
        response_time = end_time - start_time
        tokens_per_second = None
        if token_count and response_time > 0:
            tokens_per_second = token_count / response_time
            
        metrics = PerformanceMetrics(
            provider=self.provider,
            model=model,
            operation_type=operation_type,
            response_time=response_time,
            request_timestamp=datetime.fromtimestamp(start_time),
            success=success,
            error_type=error_type,
            token_count=token_count,
            tokens_per_second=tokens_per_second,
            first_token_time=first_token_time,
            stream_chunk_count=stream_chunk_count
        )
        
        performance_monitor.record_metrics(metrics)
    
    def _validate_timeout(self, timeout: Optional[int]) -> int:
        """Validate and return appropriate timeout value."""
        if timeout is None:
            return self.default_timeout
        if timeout <= 0:
            raise ConfigurationError("Timeout must be positive")
        if timeout > 300:  # 5 minute maximum
            logger.warning(f"Timeout {timeout}s exceeds recommended maximum of 300s")
        return timeout
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics for this client."""
        with self._lock:
            return {
                'provider': self.provider.value,
                'request_count': self._request_count,
                'is_validated': self._validated,
                'default_timeout': self.default_timeout,
                'performance_monitoring_enabled': self.enable_performance_monitoring,
                'caching_enabled': self.enable_caching,
                'provider_key': getattr(self, '_provider_key', None),
                'recovery_enabled': RECOVERY_AVAILABLE
            }
    
    def generate_response_with_recovery(
        self, 
        messages: List[Dict[str, str]], 
        **kwargs
    ) -> AIResponse:
        """
        Generate response with error recovery mechanisms.
        
        This method wraps the standard generate_response with comprehensive
        error recovery including retries, circuit breaker, and fallback suggestions.
        
        Args:
            messages: List of conversation messages
            **kwargs: Provider-specific parameters
            
        Returns:
            AIResponse: Standardized response object
            
        Raises:
            Exception: If all recovery mechanisms fail
        """
        if not RECOVERY_AVAILABLE:
            # Fallback to standard method if recovery not available
            return self.generate_response(messages, **kwargs)
        
        try:
            recovery_orchestrator = get_error_recovery()
            
            def operation():
                return self.generate_response(messages, **kwargs)
            
            return recovery_orchestrator.execute_with_recovery(
                operation=operation,
                provider=self.provider,
                model=kwargs.get('model', self._get_model_name()),
                api_key=self.api_key
            )
            
        except Exception as e:
            # Add fallback suggestions if available
            if hasattr(e, 'fallback_suggestions'):
                logger.info(f"Fallback suggestions available: {len(e.fallback_suggestions)} options")
            
            # Record failure for performance tracking
            self._record_performance_metrics(
                operation_type='generate_response_with_recovery',
                start_time=time.time(),
                end_time=time.time(),
                success=False,
                model=kwargs.get('model', self._get_model_name()),
                error_type=type(e).__name__
            )
            
            raise
    
    def generate_response_stream_with_recovery(
        self, 
        messages: List[Dict[str, str]], 
        **kwargs
    ) -> Iterator[str]:
        """
        Generate streaming response with error recovery mechanisms.
        
        Args:
            messages: List of conversation messages  
            **kwargs: Provider-specific parameters
            
        Yields:
            str: Response content chunks
            
        Raises:
            Exception: If all recovery mechanisms fail
        """
        if not RECOVERY_AVAILABLE:
            # Fallback to standard method if recovery not available
            yield from self.generate_response_stream(messages, **kwargs)
            return
        
        try:
            recovery_orchestrator = get_error_recovery()
            
            def operation():
                # For streaming, we need to handle the iterator differently
                return list(self.generate_response_stream(messages, **kwargs))
            
            result_chunks = recovery_orchestrator.execute_with_recovery(
                operation=operation,
                provider=self.provider,
                model=kwargs.get('model', self._get_model_name()),
                api_key=self.api_key
            )
            
            # Yield the chunks from the recovered operation
            for chunk in result_chunks:
                yield chunk
                
        except Exception as e:
            # Add fallback suggestions if available
            if hasattr(e, 'fallback_suggestions'):
                logger.info(f"Fallback suggestions available: {len(e.fallback_suggestions)} options")
            
            # Record failure for performance tracking
            self._record_performance_metrics(
                operation_type='generate_response_stream_with_recovery',
                start_time=time.time(),
                end_time=time.time(),
                success=False,
                model=kwargs.get('model', self._get_model_name()),
                error_type=type(e).__name__
            )
            
            raise


class DeepSeekClient(BaseAIClient):
    """
    DeepSeek AI client implementation using OpenAI-compatible API.
    
    This client maintains compatibility with the existing DeepSeek integration
    while providing the standardized interface defined by BaseAIClient.
    """
    
    def __init__(self, api_key: str, base_url: str = "https://api.deepseek.com", **kwargs):
        """
        Initialize DeepSeek client.
        
        Args:
            api_key (str): DeepSeek API key
            base_url (str): Base URL for DeepSeek API
            **kwargs: Additional OpenAI client parameters
        """
        super().__init__(api_key, **kwargs)
        self.base_url = base_url
        self._client = None
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize the OpenAI-compatible client for DeepSeek."""
        try:
            from openai import OpenAI
            
            # Try different initialization approaches for compatibility
            init_attempts = [
                {
                    'params': {'api_key': self.api_key, 'base_url': self.base_url},
                    'description': 'DeepSeek API with base_url'
                },
                {
                    'params': {'api_key': self.api_key},
                    'description': 'Direct OpenAI client initialization'
                }
            ]
            
            for attempt in init_attempts:
                try:
                    logger.info(f"Attempting DeepSeek client initialization: {attempt['description']}")
                    self._client = OpenAI(**attempt['params'])
                    
                    # Test that the client can be accessed
                    _ = self._client.chat
                    logger.info(f"✅ DeepSeek client initialized successfully: {attempt['description']}")
                    break
                except Exception as e:
                    logger.warning(f"❌ Failed to initialize {attempt['description']}: {e}")
                    self._client = None
                    continue
            
            if not self._client:
                raise ConfigurationError("All DeepSeek client initialization attempts failed")
                
        except ImportError:
            raise ConfigurationError("OpenAI library not installed. Please run: pip install openai")
    
    def generate_response(
        self, 
        messages: List[Dict[str, str]], 
        model: str = "deepseek-chat",
        temperature: float = 0.7,
        max_tokens: int = 1000,
        timeout: Optional[int] = None,
        **kwargs
    ) -> AIResponse:
        """Generate a complete response from DeepSeek with performance monitoring."""
        if not self._client:
            raise ConfigurationError("DeepSeek client not initialized")
        
        # Validate and set timeout
        validated_timeout = self._validate_timeout(timeout)
        
        start_time = time.time()
        request_timestamp = datetime.now()
        
        with self._lock:
            self._request_count += 1
        
        try:
            response = self._client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=validated_timeout,
                **kwargs
            )
            
            end_time = time.time()
            response_timestamp = datetime.now()
            response_time = end_time - start_time
            
            # Extract response content
            content = response.choices[0].message.content
            finish_reason = response.choices[0].finish_reason
            
            # Extract usage information if available
            usage = None
            token_count = None
            if hasattr(response, 'usage') and response.usage:
                usage = {
                    'prompt_tokens': response.usage.prompt_tokens,
                    'completion_tokens': response.usage.completion_tokens,
                    'total_tokens': response.usage.total_tokens
                }
                token_count = response.usage.total_tokens
            
            # Record performance metrics
            self._record_performance_metrics(
                operation_type='generate_response',
                start_time=start_time,
                end_time=end_time,
                success=True,
                model=model,
                token_count=token_count
            )
            
            return AIResponse(
                content=content,
                model=model,
                provider=AIProvider.DEEPSEEK,
                usage=usage,
                response_time=response_time,
                finish_reason=finish_reason,
                request_timestamp=request_timestamp,
                response_timestamp=response_timestamp
            )
            
        except Exception as e:
            end_time = time.time()
            error_msg = str(e).lower()
            error_type = None
            
            if "authentication" in error_msg or "api_key" in error_msg:
                error_type = "authentication"
                exception_to_raise = AuthenticationError(f"DeepSeek authentication failed: {e}")
            elif "timeout" in error_msg:
                error_type = "timeout"
                exception_to_raise = TimeoutError(f"DeepSeek API timeout after {validated_timeout}s: {e}")
            elif "rate" in error_msg or "limit" in error_msg:
                error_type = "rate_limit"
                exception_to_raise = APIError(f"DeepSeek rate limit exceeded: {e}")
            else:
                error_type = "api_error"
                exception_to_raise = APIError(f"DeepSeek API error: {e}")
            
            # Record failed performance metrics
            self._record_performance_metrics(
                operation_type='generate_response',
                start_time=start_time,
                end_time=end_time,
                success=False,
                model=model,
                error_type=error_type
            )
            
            raise exception_to_raise
    
    def generate_response_stream(
        self, 
        messages: List[Dict[str, str]], 
        model: str = "deepseek-chat",
        temperature: float = 0.7,
        max_tokens: int = 1000,
        timeout: Optional[int] = None,
        **kwargs
    ) -> Iterator[str]:
        """Generate a streaming response from DeepSeek with performance monitoring."""
        if not self._client:
            raise ConfigurationError("DeepSeek client not initialized")
        
        # Validate and set timeout
        validated_timeout = self._validate_timeout(timeout)
        
        start_time = time.time()
        first_token_time = None
        chunk_count = 0
        
        with self._lock:
            self._request_count += 1
        
        try:
            response = self._client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=validated_timeout,
                stream=True,
                **kwargs
            )
            
            for chunk in response:
                if chunk.choices and len(chunk.choices) > 0:
                    delta = chunk.choices[0].delta
                    if hasattr(delta, 'content') and delta.content:
                        if first_token_time is None:
                            first_token_time = time.time() - start_time
                        chunk_count += 1
                        yield delta.content
                    
                    # Check if stream is finished
                    if chunk.choices[0].finish_reason is not None:
                        break
            
            # Record successful streaming metrics
            end_time = time.time()
            self._record_performance_metrics(
                operation_type='generate_response_stream',
                start_time=start_time,
                end_time=end_time,
                success=True,
                model=model,
                first_token_time=first_token_time,
                stream_chunk_count=chunk_count
            )
                        
        except Exception as e:
            end_time = time.time()
            error_msg = str(e).lower()
            error_type = None
            
            if "authentication" in error_msg or "api_key" in error_msg:
                error_type = "authentication"
                exception_to_raise = AuthenticationError(f"DeepSeek authentication failed: {e}")
            elif "timeout" in error_msg:
                error_type = "timeout"
                exception_to_raise = TimeoutError(f"DeepSeek API timeout after {validated_timeout}s: {e}")
            elif "rate" in error_msg or "limit" in error_msg:
                error_type = "rate_limit"
                exception_to_raise = APIError(f"DeepSeek rate limit exceeded: {e}")
            else:
                error_type = "api_error"
                exception_to_raise = APIError(f"DeepSeek API error: {e}")
            
            # Record failed streaming metrics
            self._record_performance_metrics(
                operation_type='generate_response_stream',
                start_time=start_time,
                end_time=end_time,
                success=False,
                model=model,
                error_type=error_type,
                first_token_time=first_token_time,
                stream_chunk_count=chunk_count
            )
            
            raise exception_to_raise
    
    def _perform_validation(self) -> bool:
        """Perform actual validation for DeepSeek API."""
        try:
            test_messages = [{"role": "user", "content": "Test connection"}]
            # Use a very short test to minimize cost and time
            if not self._client:
                self._initialize_client()
            
            response = self._client.chat.completions.create(
                model="deepseek-chat",
                messages=test_messages,
                max_tokens=1,
                timeout=10
            )
            return True
        except Exception as e:
            logger.warning(f"DeepSeek connection validation failed: {e}")
            return False
    
    def _get_fresh_model_info(self) -> ModelInfo:
        """Get fresh DeepSeek model information."""
        return ModelInfo(
            name="deepseek-chat",
            provider=AIProvider.DEEPSEEK,
            max_tokens=4096,
            supports_streaming=True,
            context_window=16384,
            description="DeepSeek's conversational AI model with reasoning capabilities"
        )
    
    def _get_model_name(self) -> str:
        """Get the current model name."""
        return "deepseek-chat"
    
    @property
    def provider(self) -> AIProvider:
        """Get provider type."""
        return AIProvider.DEEPSEEK


class GeminiClient(BaseAIClient):
    """
    Google Gemini AI client implementation.
    
    This client provides access to Google's Gemini models through the
    Google Generative AI SDK while maintaining the standardized interface.
    """
    
    def __init__(self, api_key: str, model_name: str = "gemini-1.5-flash", **kwargs):
        """
        Initialize Gemini client.
        
        Args:
            api_key (str): Google AI API key
            model_name (str): Gemini model name (gemini-1.5-flash, gemini-1.5-pro, etc.)
            **kwargs: Additional configuration parameters
        """
        super().__init__(api_key, **kwargs)
        self.model_name = model_name
        self._client = None
        self._model = None
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize the Google Generative AI client."""
        try:
            import google.generativeai as genai
            
            # Configure the API key
            genai.configure(api_key=self.api_key)
            self._client = genai
            
            # Initialize the model
            self._model = genai.GenerativeModel(self.model_name)
            logger.info(f"✅ Gemini client initialized successfully with model: {self.model_name}")
            
        except ImportError:
            raise ConfigurationError(
                "Google Generative AI library not installed. Please run: pip install google-generativeai"
            )
        except Exception as e:
            raise ConfigurationError(f"Failed to initialize Gemini client: {e}")
    
    def _convert_messages_to_gemini(self, messages: List[Dict[str, str]]) -> str:
        """
        Convert OpenAI-style messages to Gemini prompt format.
        
        Args:
            messages: List of message dictionaries
            
        Returns:
            str: Formatted prompt for Gemini
        """
        prompt_parts = []
        
        for message in messages:
            role = message.get('role', 'user')
            content = message.get('content', '')
            
            if role == 'system':
                prompt_parts.append(f"System: {content}")
            elif role == 'user':
                prompt_parts.append(f"User: {content}")
            elif role == 'assistant':
                prompt_parts.append(f"Assistant: {content}")
        
        return "\n\n".join(prompt_parts)
    
    def generate_response(
        self, 
        messages: List[Dict[str, str]], 
        temperature: float = 0.7,
        max_tokens: int = 1000,
        timeout: Optional[int] = None,
        **kwargs
    ) -> AIResponse:
        """Generate a complete response from Gemini with performance monitoring."""
        if not self._model:
            raise ConfigurationError("Gemini model not initialized")
        
        # Validate timeout (Gemini doesn't support timeout directly, but we track it)
        validated_timeout = self._validate_timeout(timeout)
        
        start_time = time.time()
        request_timestamp = datetime.now()
        
        with self._lock:
            self._request_count += 1
        
        try:
            # Convert messages to Gemini format
            prompt = self._convert_messages_to_gemini(messages)
            
            # Configure generation parameters
            generation_config = {
                'temperature': temperature,
                'max_output_tokens': max_tokens,
            }
            
            # Generate response
            response = self._model.generate_content(
                prompt,
                generation_config=generation_config
            )
            
            end_time = time.time()
            response_timestamp = datetime.now()
            response_time = end_time - start_time
            
            # Check if we exceeded our timeout threshold
            if response_time > validated_timeout:
                logger.warning(f"Gemini response took {response_time:.2f}s, exceeded timeout threshold of {validated_timeout}s")
            
            # Extract content
            content = response.text if response.text else ""
            
            # Extract usage information if available
            usage = None
            token_count = None
            if hasattr(response, 'usage_metadata') and response.usage_metadata:
                usage = {
                    'prompt_tokens': getattr(response.usage_metadata, 'prompt_token_count', 0),
                    'completion_tokens': getattr(response.usage_metadata, 'candidates_token_count', 0),
                    'total_tokens': getattr(response.usage_metadata, 'total_token_count', 0)
                }
                token_count = usage['total_tokens']
            
            # Record performance metrics
            self._record_performance_metrics(
                operation_type='generate_response',
                start_time=start_time,
                end_time=end_time,
                success=True,
                model=self.model_name,
                token_count=token_count
            )
            
            return AIResponse(
                content=content,
                model=self.model_name,
                provider=AIProvider.GEMINI,
                usage=usage,
                response_time=response_time,
                finish_reason=getattr(response, 'finish_reason', None),
                request_timestamp=request_timestamp,
                response_timestamp=response_timestamp
            )
            
        except Exception as e:
            end_time = time.time()
            error_msg = str(e).lower()
            error_type = None
            
            if "api key" in error_msg or "authentication" in error_msg:
                error_type = "authentication"
                exception_to_raise = AuthenticationError(f"Gemini authentication failed: {e}")
            elif "quota" in error_msg or "rate limit" in error_msg:
                error_type = "rate_limit"
                exception_to_raise = APIError(f"Gemini rate limit exceeded: {e}")
            elif end_time - start_time > validated_timeout:
                error_type = "timeout"
                exception_to_raise = TimeoutError(f"Gemini API timeout after {validated_timeout}s: {e}")
            else:
                error_type = "api_error"
                exception_to_raise = APIError(f"Gemini API error: {e}")
            
            # Record failed performance metrics
            self._record_performance_metrics(
                operation_type='generate_response',
                start_time=start_time,
                end_time=end_time,
                success=False,
                model=self.model_name,
                error_type=error_type
            )
            
            raise exception_to_raise
    
    def generate_response_stream(
        self, 
        messages: List[Dict[str, str]], 
        temperature: float = 0.7,
        max_tokens: int = 1000,
        timeout: Optional[int] = None,
        **kwargs
    ) -> Iterator[str]:
        """Generate a streaming response from Gemini with performance monitoring."""
        if not self._model:
            raise ConfigurationError("Gemini model not initialized")
        
        # Validate timeout
        validated_timeout = self._validate_timeout(timeout)
        
        start_time = time.time()
        first_token_time = None
        chunk_count = 0
        
        with self._lock:
            self._request_count += 1
        
        try:
            # Convert messages to Gemini format
            prompt = self._convert_messages_to_gemini(messages)
            
            # Configure generation parameters
            generation_config = {
                'temperature': temperature,
                'max_output_tokens': max_tokens,
            }
            
            # Generate streaming response
            response = self._model.generate_content(
                prompt,
                generation_config=generation_config,
                stream=True
            )
            
            for chunk in response:
                if chunk.text:
                    if first_token_time is None:
                        first_token_time = time.time() - start_time
                    chunk_count += 1
                    
                    # Check timeout during streaming
                    current_time = time.time()
                    if current_time - start_time > validated_timeout:
                        logger.warning(f"Gemini streaming exceeded timeout {validated_timeout}s")
                        break
                    
                    yield chunk.text
            
            # Record successful streaming metrics
            end_time = time.time()
            self._record_performance_metrics(
                operation_type='generate_response_stream',
                start_time=start_time,
                end_time=end_time,
                success=True,
                model=self.model_name,
                first_token_time=first_token_time,
                stream_chunk_count=chunk_count
            )
                    
        except Exception as e:
            end_time = time.time()
            error_msg = str(e).lower()
            error_type = None
            
            if "api key" in error_msg or "authentication" in error_msg:
                error_type = "authentication"
                exception_to_raise = AuthenticationError(f"Gemini authentication failed: {e}")
            elif "quota" in error_msg or "rate limit" in error_msg:
                error_type = "rate_limit"
                exception_to_raise = APIError(f"Gemini rate limit exceeded: {e}")
            elif end_time - start_time > validated_timeout:
                error_type = "timeout"
                exception_to_raise = TimeoutError(f"Gemini API timeout after {validated_timeout}s: {e}")
            else:
                error_type = "api_error"
                exception_to_raise = APIError(f"Gemini API error: {e}")
            
            # Record failed streaming metrics
            self._record_performance_metrics(
                operation_type='generate_response_stream',
                start_time=start_time,
                end_time=end_time,
                success=False,
                model=self.model_name,
                error_type=error_type,
                first_token_time=first_token_time,
                stream_chunk_count=chunk_count
            )
            
            raise exception_to_raise
    
    def _perform_validation(self) -> bool:
        """Perform actual validation for Gemini API."""
        try:
            if not self._model:
                self._initialize_client()
            
            # Test with minimal content
            response = self._model.generate_content(
                "Test",
                generation_config={'max_output_tokens': 1}
            )
            return True
        except Exception as e:
            logger.warning(f"Gemini connection validation failed: {e}")
            return False
    
    def _get_fresh_model_info(self) -> ModelInfo:
        """Get fresh Gemini model information."""
        # Model capabilities vary by model name
        max_tokens = 8192
        context_window = 32768
        
        if "pro" in self.model_name.lower():
            max_tokens = 8192
            context_window = 32768
        
        return ModelInfo(
            name=self.model_name,
            provider=AIProvider.GEMINI,
            max_tokens=max_tokens,
            supports_streaming=True,
            context_window=context_window,
            description=f"Google's {self.model_name} model with advanced reasoning capabilities"
        )
    
    def _get_model_name(self) -> str:
        """Get the current model name."""
        return self.model_name
    
    @property
    def provider(self) -> AIProvider:
        """Get provider type."""
        return AIProvider.GEMINI


class AIClientFactory:
    """
    Factory class for creating and managing AI client instances.
    
    This factory provides:
    - Client instantiation with proper validation
    - Environment variable management
    - Provider availability checking
    - Configuration validation
    """
    
    def __init__(self):
        """Initialize the factory."""
        self._clients: Dict[AIProvider, BaseAIClient] = {}
        self._validated_providers: set = set()
    
    def create_client(
        self, 
        provider: Union[AIProvider, str], 
        api_key: Optional[str] = None,
        **kwargs
    ) -> BaseAIClient:
        """
        Create an AI client for the specified provider with connection pooling support.
        
        Args:
            provider (AIProvider | str): The AI provider type
            api_key (str, optional): API key (if not provided, reads from environment)
            **kwargs: Provider-specific configuration
            
        Returns:
            BaseAIClient: Configured AI client instance
            
        Raises:
            ConfigurationError: Invalid configuration or missing dependencies
            AuthenticationError: Invalid or missing API key
        """
        # Convert string to enum if needed
        if isinstance(provider, str):
            try:
                provider = AIProvider(provider.lower())
            except ValueError:
                raise ConfigurationError(f"Unsupported provider: {provider}")
        
        # Get API key from environment if not provided
        if not api_key:
            api_key = self._get_api_key_for_provider(provider)
        
        # Validate API key
        if not self._validate_api_key(api_key, provider):
            raise AuthenticationError(f"Invalid or missing API key for {provider.value}")
        
        # Create provider key for connection pooling
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()[:16]
        provider_key = f"{provider.value}_{api_key_hash}"
        
        # Try to get from connection pool first
        def create_client_func():
            if provider == AIProvider.DEEPSEEK:
                base_url = kwargs.pop('base_url', None) or os.getenv('DEEPSEEK_BASE_URL', 'https://api.deepseek.com')
                return DeepSeekClient(api_key=api_key, base_url=base_url, **kwargs)
            elif provider == AIProvider.GEMINI:
                model_name = kwargs.pop('model_name', 'gemini-1.5-flash')
                return GeminiClient(api_key=api_key, model_name=model_name, **kwargs)
            else:
                raise ConfigurationError(f"Provider {provider.value} not implemented")
        
        # Create client directly - connection pooling disabled for simplicity
        try:
            client = create_client_func()
        except Exception as e:
            logger.error(f"Failed to create client for {provider.value}: {e}")
            raise
        
        # Cache the client reference
        self._clients[provider] = client
        
        return client
    
    def get_client(self, provider: Union[AIProvider, str]) -> Optional[BaseAIClient]:
        """
        Get an existing client instance.
        
        Args:
            provider (AIProvider | str): The AI provider type
            
        Returns:
            BaseAIClient | None: Existing client or None if not found
        """
        if isinstance(provider, str):
            try:
                provider = AIProvider(provider.lower())
            except ValueError:
                return None
        
        return self._clients.get(provider)
    
    def validate_provider_credentials(self, provider: Union[AIProvider, str]) -> bool:
        """
        Validate credentials for a specific provider.
        
        Args:
            provider (AIProvider | str): The AI provider type
            
        Returns:
            bool: True if credentials are valid, False otherwise
        """
        try:
            client = self.create_client(provider)
            is_valid = client.validate_connection()
            if is_valid:
                self._validated_providers.add(client.provider)
            return is_valid
        except Exception as e:
            logger.warning(f"Credential validation failed for {provider}: {e}")
            return False
    
    def get_available_providers(self) -> List[AIProvider]:
        """
        Get list of available providers with valid credentials.
        
        Returns:
            List[AIProvider]: List of available providers
        """
        available = []
        
        for provider in AIProvider:
            if self.validate_provider_credentials(provider):
                available.append(provider)
        
        return available
    
    def get_model_info_for_provider(self, provider: Union[AIProvider, str]) -> Optional[ModelInfo]:
        """
        Get model information for a specific provider.
        
        Args:
            provider (AIProvider | str): The AI provider type
            
        Returns:
            ModelInfo | None: Model information or None if provider unavailable
        """
        try:
            client = self.get_client(provider) or self.create_client(provider)
            return client.get_model_info()
        except Exception as e:
            logger.warning(f"Failed to get model info for {provider}: {e}")
            return None
    
    def _get_api_key_for_provider(self, provider: AIProvider) -> Optional[str]:
        """Get API key from environment for the specified provider."""
        env_var_map = {
            AIProvider.DEEPSEEK: 'DEEPSEEK_API_KEY',
            AIProvider.GEMINI: 'GEMINI_API_KEY'
        }
        
        env_var = env_var_map.get(provider)
        if not env_var:
            return None
        
        return os.getenv(env_var)
    
    def _validate_api_key(self, api_key: Optional[str], provider: AIProvider) -> bool:
        """
        Validate API key format and basic requirements.
        
        Args:
            api_key (str): API key to validate
            provider (AIProvider): Provider type for validation rules
            
        Returns:
            bool: True if API key appears valid, False otherwise
        """
        if not api_key or not api_key.strip():
            return False
        
        api_key = api_key.strip()
        
        # Basic length validation
        if len(api_key) < 10:
            return False
        
        # Provider-specific validation
        if provider == AIProvider.DEEPSEEK:
            # DeepSeek API keys typically start with 'sk-'
            return api_key.startswith('sk-') and len(api_key) > 20
        elif provider == AIProvider.GEMINI:
            # Google API keys are typically 39 characters long
            return len(api_key) >= 30 and not api_key.startswith('sk-')
        
        return True
    
    def validate_environment_variables(self) -> Dict[str, bool]:
        """
        Validate all required environment variables.
        
        Returns:
            Dict[str, bool]: Validation results for each provider
        """
        results = {}
        
        # Check DEEPSEEK_API_KEY
        deepseek_key = os.getenv('DEEPSEEK_API_KEY')
        results['DEEPSEEK_API_KEY'] = self._validate_api_key(deepseek_key, AIProvider.DEEPSEEK)
        
        # Check GEMINI_API_KEY
        gemini_key = os.getenv('GEMINI_API_KEY')
        results['GEMINI_API_KEY'] = self._validate_api_key(gemini_key, AIProvider.GEMINI)
        
        return results


# Factory instance for global use
ai_factory = AIClientFactory()


def get_ai_client(provider: Union[AIProvider, str], **kwargs) -> BaseAIClient:
    """
    Convenience function to get an AI client instance.
    
    Args:
        provider (AIProvider | str): The AI provider type
        **kwargs: Additional configuration options
        
    Returns:
        BaseAIClient: Configured AI client instance
    """
    return ai_factory.create_client(provider, **kwargs)


def validate_all_providers() -> Dict[AIProvider, bool]:
    """
    Validate all supported providers.
    
    Returns:
        Dict[AIProvider, bool]: Validation results for each provider
    """
    results = {}
    for provider in AIProvider:
        results[provider] = ai_factory.validate_provider_credentials(provider)
    return results