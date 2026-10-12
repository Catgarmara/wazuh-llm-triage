#!/usr/bin/env python3
"""
OpenSearch connector - Simple connection and query functions.
That's it. Just connects and queries. Nothing else.
"""

import os
import requests
import logging
import re
import json
from typing import Dict, Any, List, Optional, Set
from datetime import datetime

logger = logging.getLogger(__name__)

# Global cache for mapping discovery to avoid re-discovery on every instantiation
_mapping_cache = {
    'mappings': {},
    'categories': {},
    'context': '',
    'last_discovery': None,
    'cache_duration': 3600  # Cache for 1 hour
}


class OpenSearchConnector:
    """Simple OpenSearch connector - connects and queries, nothing more"""
    
    def __init__(self):
        """Initialize with connection settings from environment"""
        self.host = os.getenv('OPENSEARCH_HOST', 'localhost')
        self.port = os.getenv('OPENSEARCH_PORT', '9200')
        self.username = os.getenv('OPENSEARCH_USER', 'admin')
        self.password = os.getenv('OPENSEARCH_PASSWORD', 'admin')
        self.ssl = os.getenv('OPENSEARCH_SSL', 'false').lower() == 'true'
        
        self.protocol = "https" if self.ssl else "http"
        self.base_url = f"{self.protocol}://{self.host}:{self.port}"
        
        # Discover all configured indices from environment
        self.indices = self._discover_indices()
        # Keep backward compatibility with single OPENSEARCH_INDEX
        self.index_pattern = os.getenv('OPENSEARCH_INDEX', 'waf-*')
        
        # Initialize mapping discovery
        self.mappings_cache = {}
        self.field_categories = {}
        self.mapping_context = ""
        
        # Discover mappings on initialization
        self._discover_all_mappings()
    
    def _discover_indices(self) -> Dict[str, str]:
        """
        Discover all OPENSEARCH_*_INDEX environment variables.
        
        Returns:
            Dictionary mapping index names to patterns
        """
        indices = {}
        
        # Scan environment for all OPENSEARCH_*_INDEX variables
        for key, value in os.environ.items():
            if key.startswith('OPENSEARCH_') and key.endswith('_INDEX'):
                # Extract the middle part as the index name
                # OPENSEARCH_WAF_INDEX -> 'waf'
                # OPENSEARCH_AUTH_INDEX -> 'auth'
                # OPENSEARCH_INDEX -> 'default'
                if key == 'OPENSEARCH_INDEX':
                    indices['default'] = value
                else:
                    # Remove OPENSEARCH_ prefix and _INDEX suffix
                    index_name = key[11:-6].lower()  # 11 = len('OPENSEARCH_'), 6 = len('_INDEX')
                    indices[index_name] = value
        
        # If no indices found, use the default
        if not indices and os.getenv('OPENSEARCH_INDEX'):
            indices['default'] = os.getenv('OPENSEARCH_INDEX', 'waf-*')
        
        return indices
    
    def get_configured_indices(self) -> Dict[str, str]:
        """
        Get all configured index patterns from environment.
        
        Returns:
            Dictionary of index names to patterns
        """
        return self.indices.copy()
    
    def query(self, query_json: Dict[str, Any], index: Optional[str] = None) -> Optional[Dict]:
        """
        Execute a query against OpenSearch.
        
        Args:
            query_json: The OpenSearch query in JSON format
            index: Optional index name or pattern. Can be:
                   - An index name from configured indices (e.g., 'waf', 'auth')
                   - A direct index pattern (e.g., 'logs-*')
                   - None to use the default
            
        Returns:
            Query results or None if failed
        """
        if index is None:
            index = self.index_pattern
        elif index in self.indices:
            # If it's a configured index name, use its pattern
            index = self.indices[index]
            
        # Try common OpenSearch API paths
        search_urls = [
            f"{self.base_url}/api/console/proxy?path=/{index}/_search&method=POST",
            f"{self.base_url}/{index}/_search",
            f"{self.base_url}/_search",
        ]
        
        for search_url in search_urls:
            try:
                headers = {'Content-Type': 'application/json'}
                if '/api/console/proxy' in search_url:
                    headers['osd-xsrf'] = 'true'
                
                response = requests.post(
                    search_url,
                    auth=(self.username, self.password),
                    verify=False,
                    timeout=30,
                    headers=headers,
                    json=query_json
                )
                
                if response.status_code == 200:
                    return response.json()
                    
            except Exception as e:
                logger.debug(f"Query attempt failed for {search_url}: {e}")
                continue
                
        return None
    
    def get_indices(self) -> List[Dict]:
        """
        Get list of available indices.
        
        Returns:
            List of index information or empty list if failed
        """
        # Try common paths for indices endpoint
        indices_urls = [
            f"{self.base_url}/api/console/proxy?path=/_cat/indices&method=GET&format=json",
            f"{self.base_url}/_cat/indices?format=json",
        ]
        
        for indices_url in indices_urls:
            try:
                headers = {'Content-Type': 'application/json'}
                if '/api/console/proxy' in indices_url:
                    headers['osd-xsrf'] = 'true'
                
                response = requests.get(
                    indices_url,
                    auth=(self.username, self.password),
                    verify=False,
                    timeout=10,
                    headers=headers
                )
                
                if response.status_code == 200:
                    indices_data = response.json()
                    
                    # Parse and filter system indices
                    result = []
                    for index_info in indices_data:
                        index_name = index_info.get('index', '')
                        if not index_name.startswith('.'):
                            result.append({
                                "name": index_name,
                                "doc_count": int(index_info.get('docs.count', '0') or '0'),
                                "size": index_info.get('store.size', '0'),
                                "status": index_info.get('status', 'unknown')
                            })
                    
                    return sorted(result, key=lambda x: x['doc_count'], reverse=True)
                    
            except Exception as e:
                logger.debug(f"Indices attempt failed for {indices_url}: {e}")
                continue
                
        return []
    
    def get_mapping(self, index: str) -> Optional[Dict]:
        """
        Get field mappings for an index.
        
        Args:
            index: Index name
            
        Returns:
            Mapping information or None if failed
        """
        mapping_urls = [
            f"{self.base_url}/api/console/proxy?path=/{index}/_mapping&method=GET",
            f"{self.base_url}/{index}/_mapping"
        ]
        
        for mapping_url in mapping_urls:
            try:
                headers = {'Content-Type': 'application/json'}
                if '/api/console/proxy' in mapping_url:
                    headers['osd-xsrf'] = 'true'
                
                response = requests.get(
                    mapping_url,
                    auth=(self.username, self.password),
                    verify=False,
                    timeout=10,
                    headers=headers
                )
                
                if response.status_code == 200:
                    return response.json()
                    
            except Exception as e:
                logger.debug(f"Mapping attempt failed for {mapping_url}: {e}")
                continue
                
        return None
    
    def _discover_all_mappings(self):
        """
        Discover mappings for all configured indices and build AI context.
        This runs on initialization to prepare field information.
        Uses caching to avoid re-discovery on every instantiation.
        """
        global _mapping_cache
        
        if not self.indices:
            logger.warning("No indices configured, skipping mapping discovery")
            return
        
        # Check if we have a valid cache
        if (_mapping_cache['last_discovery'] and 
            _mapping_cache['mappings'] and
            (datetime.now() - _mapping_cache['last_discovery']).total_seconds() < _mapping_cache['cache_duration']):
            # Use cached mappings
            logger.info("Using cached OpenSearch mappings")
            self.mappings_cache = _mapping_cache['mappings'].copy()
            self.field_categories = _mapping_cache['categories'].copy()
            self.mapping_context = _mapping_cache['context']
            return
            
        logger.info(f"Discovering mappings for {len(self.indices)} configured indices")
        
        for index_name, index_pattern in self.indices.items():
            try:
                mapping = self.get_mapping(index_pattern)
                if mapping:
                    # Extract fields from the mapping
                    fields = self._extract_fields_from_mapping(mapping, index_pattern)
                    self.mappings_cache[index_name] = fields
                    logger.info(f"Discovered {len(fields)} fields for index {index_name} ({index_pattern})")
                else:
                    logger.warning(f"Could not get mapping for index {index_name} ({index_pattern})")
                    self.mappings_cache[index_name] = {}
            except Exception as e:
                logger.error(f"Error discovering mapping for {index_name}: {e}")
                self.mappings_cache[index_name] = {}
        
        # Categorize fields by purpose
        self._categorize_fields()
        
        # Generate AI context
        self.mapping_context = self._generate_ai_context()
        
        # Update cache
        _mapping_cache['mappings'] = self.mappings_cache.copy()
        _mapping_cache['categories'] = self.field_categories.copy()
        _mapping_cache['context'] = self.mapping_context
        _mapping_cache['last_discovery'] = datetime.now()
        
        logger.info("Mapping discovery complete and cached")
    
    def _extract_fields_from_mapping(self, mapping: Dict, index_pattern: str) -> Dict[str, str]:
        """
        Extract field names and types from OpenSearch mapping response.
        
        Args:
            mapping: Raw mapping response from OpenSearch
            index_pattern: The index pattern used
            
        Returns:
            Dictionary of field_name -> field_type
        """
        fields = {}
        
        # OpenSearch returns mappings keyed by actual index name(s)
        # We need to handle patterns like waf-* that might return multiple indices
        for index_name, index_data in mapping.items():
            if 'mappings' in index_data:
                properties = index_data['mappings'].get('properties', {})
                self._extract_fields_recursive(properties, '', fields)
                break  # Use first index as representative
        
        return fields
    
    def _extract_fields_recursive(self, properties: Dict, prefix: str, fields: Dict):
        """
        Recursively extract fields from nested mapping properties.
        
        Args:
            properties: Properties dict from mapping
            prefix: Current field prefix for nested fields
            fields: Output dict to populate
        """
        for field_name, field_def in properties.items():
            full_name = f"{prefix}{field_name}" if prefix else field_name
            
            if 'type' in field_def:
                fields[full_name] = field_def['type']
            
            # Handle nested objects
            if 'properties' in field_def:
                self._extract_fields_recursive(
                    field_def['properties'], 
                    f"{full_name}.", 
                    fields
                )
    
    def _categorize_fields(self):
        """
        Categorize fields by their purpose using pattern matching.
        This helps AI understand which fields to use for different queries.
        """
        # Define patterns for field categorization
        patterns = {
            'ip_fields': [
                re.compile(r'.*\.ip$'),
                re.compile(r'^ip$'),
                re.compile(r'.*_ip$'),
                re.compile(r'^remote$'),
                re.compile(r'^client.*'),
                re.compile(r'^source.*'),
                re.compile(r'^dest.*'),
                re.compile(r'^src.*'),
                re.compile(r'^dst.*'),
                re.compile(r'.*address$'),
            ],
            'timestamp_fields': [
                re.compile(r'.*time.*'),
                re.compile(r'.*date.*'),
                re.compile(r'^@timestamp$'),
                re.compile(r'^timestamp$'),
            ],
            'user_fields': [
                re.compile(r'^user.*'),
                re.compile(r'.*username.*'),
                re.compile(r'.*account.*'),
                re.compile(r'.*login.*'),
                re.compile(r'^uid$'),
            ],
            'status_fields': [
                re.compile(r'.*status.*'),
                re.compile(r'.*code$'),
                re.compile(r'.*result.*'),
                re.compile(r'.*outcome.*'),
                re.compile(r'.*response.*'),
            ],
            'url_fields': [
                re.compile(r'.*url.*'),
                re.compile(r'.*uri.*'),
                re.compile(r'.*path.*'),
                re.compile(r'.*request.*'),
                re.compile(r'.*endpoint.*'),
            ],
            'message_fields': [
                re.compile(r'.*message.*'),
                re.compile(r'.*msg$'),
                re.compile(r'.*text$'),
                re.compile(r'.*description.*'),
                re.compile(r'.*error.*'),
            ]
        }
        
        # Categorize fields for each index
        for index_name, fields in self.mappings_cache.items():
            self.field_categories[index_name] = {category: [] for category in patterns.keys()}
            
            for field_name, field_type in fields.items():
                field_lower = field_name.lower()
                
                for category, pattern_list in patterns.items():
                    for pattern in pattern_list:
                        if pattern.match(field_lower):
                            self.field_categories[index_name][category].append(field_name)
                            break
    
    def _generate_ai_context(self) -> str:
        """
        Generate comprehensive context for AI about available fields.
        
        Returns:
            Context string to inject into AI prompts
        """
        if not self.mappings_cache:
            return "No OpenSearch indices discovered."
        
        context = "\n=== OpenSearch Index Field Mappings ===\n\n"
        context += "Available indices and their fields:\n\n"
        
        for index_name, fields in self.mappings_cache.items():
            index_pattern = self.indices.get(index_name, 'unknown')
            context += f"Index: '{index_name}' (pattern: {index_pattern})\n"
            
            if not fields:
                context += "  No fields discovered\n\n"
                continue
            
            # Show categorized fields
            if index_name in self.field_categories:
                categories = self.field_categories[index_name]
                
                # Show IP fields first (most important for security queries)
                if categories.get('ip_fields'):
                    context += f"  IP address fields: {', '.join(categories['ip_fields'][:5])}\n"
                
                if categories.get('timestamp_fields'):
                    context += f"  Timestamp fields: {', '.join(categories['timestamp_fields'][:3])}\n"
                
                if categories.get('user_fields'):
                    context += f"  User fields: {', '.join(categories['user_fields'][:3])}\n"
                
                if categories.get('url_fields'):
                    context += f"  URL/Path fields: {', '.join(categories['url_fields'][:3])}\n"
                
                if categories.get('status_fields'):
                    context += f"  Status fields: {', '.join(categories['status_fields'][:3])}\n"
            
            # Show total field count
            context += f"  Total fields: {len(fields)}\n"
            
            # List some key fields with types
            context += "  Sample fields:\n"
            sample_count = 0
            for field_name, field_type in sorted(fields.items())[:10]:
                context += f"    - {field_name} ({field_type})\n"
                sample_count += 1
            
            if len(fields) > sample_count:
                context += f"    ... and {len(fields) - sample_count} more fields\n"
            
            context += "\n"
        
        # Add query guidelines
        context += "=== Query Guidelines ===\n"
        context += "- Use the exact field names shown above\n"
        context += "- For IP searches, check the 'IP address fields' for each index\n"
        context += "- Timestamp fields vary by index - use the discovered field names\n"
        context += "- Field names are case-sensitive\n\n"
        
        # Add examples if we have discovered fields
        if self.field_categories:
            context += "=== Query Examples Based on Discovered Fields ===\n"
            
            for index_name, categories in self.field_categories.items():
                if categories.get('ip_fields') and categories['ip_fields']:
                    ip_field = categories['ip_fields'][0]
                    context += f"For IP search in {index_name}: "
                    context += f'{{"query": {{"term": {{"{ip_field}": "192.168.1.1"}}}}}}\n'
                    break
        
        return context
    
    def get_mapping_context(self) -> str:
        """
        Get the generated mapping context for AI.
        
        Returns:
            The mapping context string
        """
        return self.mapping_context
    
    def refresh_mappings(self):
        """
        Refresh the mapping cache by re-discovering all mappings.
        Useful if indices have changed.
        """
        global _mapping_cache
        logger.info("Refreshing OpenSearch mappings")
        
        # Clear the global cache to force re-discovery
        _mapping_cache['last_discovery'] = None
        _mapping_cache['mappings'] = {}
        _mapping_cache['categories'] = {}
        _mapping_cache['context'] = ''
        
        # Clear instance cache
        self.mappings_cache = {}
        self.field_categories = {}
        
        # Re-discover
        self._discover_all_mappings()


# Keep backward compatibility functions
def query_opensearch(query=None):
    """Execute OpenSearch query - backward compatibility"""
    connector = OpenSearchConnector()
    
    if query is None:
        # Default query for testing
        query = {"query": {"match_all": {}}, "size": 10}
    
    return connector.query(query)


def get_available_indices():
    """Get available indices - backward compatibility"""
    connector = OpenSearchConnector()
    return connector.get_indices()