#!/usr/bin/env python3
"""
Base connector interface for SIEM integrations.
Simple abstract base class for standardizing SIEM connector implementations.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)


class SIEMConnectorError(Exception):
    """Base exception for SIEM connector errors"""
    pass


class ConnectionError(SIEMConnectorError):
    """Raised when connection to SIEM fails"""
    pass


class QueryError(SIEMConnectorError):
    """Raised when query execution fails"""
    pass


class BaseSIEMConnector(ABC):
    """
    Abstract base class for SIEM connectors.
    
    Defines the standard interface that all SIEM connectors must implement.
    Keeps it simple - connect, query, disconnect.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize connector with configuration"""
        self.config = config
        self._connected = False
    
    @abstractmethod
    def connect(self, config: Optional[Dict[str, Any]] = None) -> bool:
        """
        Establish connection to SIEM.
        
        Args:
            config: Optional connection config to override instance config
            
        Returns:
            bool: True if connection successful
            
        Raises:
            ConnectionError: If connection fails
        """
        pass
    
    @abstractmethod
    def query(self, query_params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a query against the SIEM.
        
        Args:
            query_params: Query parameters specific to the SIEM
            
        Returns:
            Dict containing query results
            
        Raises:
            QueryError: If query execution fails
        """
        pass
    
    @abstractmethod
    def disconnect(self) -> None:
        """
        Close connection to SIEM.
        
        Should handle cleanup and resource disposal.
        """
        pass
    
    @property
    def is_connected(self) -> bool:
        """Check if connector is currently connected"""
        return self._connected