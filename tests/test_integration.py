#!/usr/bin/env python3
"""
Integration Test for TASK-018: Connector Pattern and Alerts
Tests core functionality of the simplified architecture in ~100 lines.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock
import json
import tempfile
import sqlite3

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

# Import modules to test
from connectors.opensearch import query_opensearch, get_available_indices, get_savedcard_abuse_query, parse_size_to_bytes
from alert_store import save_alert, get_alerts, get_alert_by_id
from ai_handler import init_ai_client, chat_completion, analyze_security_alert, get_client_status
from app import app


class TestOpenSearchConnector(unittest.TestCase):
    """Test OpenSearch connector functionality"""
    
    @patch('connectors.opensearch.requests.post')
    def test_query_opensearch_success(self, mock_post):
        """Test successful OpenSearch query"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"hits": {"total": {"value": 10}}}
        mock_post.return_value = mock_response
        
        result = query_opensearch()
        self.assertIsNotNone(result)
        self.assertEqual(result["hits"]["total"]["value"], 10)
    
    @patch('connectors.opensearch.requests.get')
    def test_get_indices_success(self, mock_get):
        """Test index discovery"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"index": "waf-logs", "docs.count": "1000", "store.size": "1.2mb"}
        ]
        mock_get.return_value = mock_response
        
        indices = get_available_indices()
        self.assertEqual(len(indices), 1)
        self.assertEqual(indices[0]["name"], "waf-logs")
        self.assertEqual(indices[0]["doc_count"], 1000)
    
    def test_parse_size_to_bytes(self):
        """Test size parsing utility"""
        self.assertEqual(parse_size_to_bytes("1kb"), 1024)
        self.assertEqual(parse_size_to_bytes("1.5mb"), int(1.5 * 1024 * 1024))
        self.assertEqual(parse_size_to_bytes("0"), 0)


class TestAlertStorage(unittest.TestCase):
    """Test alert storage functionality"""
    
    def setUp(self):
        """Create temporary database for testing"""
        self.test_db_path = tempfile.mktemp(suffix='.db')
        # Patch the connection function to use our test database
        import alert_store
        self.original_connect = alert_store._get_db_connection
        alert_store._get_db_connection = lambda: sqlite3.connect(self.test_db_path)
    
    def tearDown(self):
        """Clean up test database"""
        import alert_store
        alert_store._get_db_connection = self.original_connect
        if os.path.exists(self.test_db_path):
            os.unlink(self.test_db_path)
    
    def test_save_and_retrieve_alert(self):
        """Test saving and retrieving alerts"""
        test_alert = {"id": "TEST_001", "event_type": "test_alert"}
        
        # Save alert
        alert_id = save_alert(test_alert, "Test AI response")
        self.assertIsNotNone(alert_id)
        
        # Retrieve by ID
        retrieved = get_alert_by_id(alert_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["alert_data"]["id"], "TEST_001")
        self.assertEqual(retrieved["ai_response"], "Test AI response")
        
        # Get all alerts
        alerts = get_alerts(10)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["id"], alert_id)


class TestAIHandler(unittest.TestCase):
    """Test AI handler with and without SOC context"""
    
    @patch('ai_handler.get_ai_client')
    @patch('os.getenv')
    def test_init_ai_client_success(self, mock_getenv, mock_get_client):
        """Test AI client initialization"""
        mock_getenv.return_value = "test-api-key"
        mock_client = MagicMock()
        mock_client.validate_connection.return_value = True
        mock_get_client.return_value = mock_client
        
        result = init_ai_client('deepseek')
        self.assertTrue(result)
        
        status = get_client_status()
        self.assertTrue(status["initialized"])
        self.assertEqual(status["provider"], "deepseek")
    
    @patch('ai_handler._ai_client')
    def test_chat_completion_with_soc(self, mock_client):
        """Test chat completion with SOC context"""
        mock_response = MagicMock()
        mock_response.content = "SOC analysis response"
        mock_response.model = "deepseek-chat"
        mock_client.generate_response.return_value = mock_response
        
        import ai_handler
        ai_handler._current_provider = "deepseek"
        
        messages = [{"role": "user", "content": "Analyze this alert"}]
        response = chat_completion(messages, include_soc_context=True)
        
        self.assertEqual(response["content"], "SOC analysis response")
        self.assertTrue(response["soc_context_applied"])
        self.assertEqual(response["provider"], "deepseek")
    
    @patch('ai_handler._ai_client')
    @patch('ai_handler.save_alert')
    def test_analyze_security_alert(self, mock_save, mock_client):
        """Test security alert analysis"""
        mock_response = MagicMock()
        mock_response.content = "CRITICAL risk level detected. Immediate action required."
        mock_response.model = "deepseek-chat"
        mock_client.generate_response.return_value = mock_response
        mock_save.return_value = 123
        
        import ai_handler
        ai_handler._current_provider = "deepseek"
        
        test_alert = {"id": "ALERT_001", "source_ip": "192.168.1.100"}
        result = analyze_security_alert(test_alert)
        
        self.assertEqual(result["risk_level"], "Critical")
        self.assertEqual(result["stored_alert_id"], 123)
        self.assertIn("analysis", result)


class TestMainRoutes(unittest.TestCase):
    """Test main Flask application routes"""
    
    def setUp(self):
        """Set up test client"""
        self.app = app.test_client()
        self.app.testing = True
    
    def test_homepage_route(self):
        """Test homepage loads"""
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)
    
    def test_health_route(self):
        """Test health check endpoint"""
        response = self.app.get('/health')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "healthy")
    
    @patch('app.get_available_indices')
    def test_opensearch_indices_route(self, mock_indices):
        """Test OpenSearch indices endpoint"""
        mock_indices.return_value = [{"name": "test-index", "doc_count": 100}]
        
        response = self.app.get('/opensearch/indices')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(len(data["indices"]), 1)
        self.assertEqual(data["indices"][0]["name"], "test-index")


if __name__ == '__main__':
    print("Running integration tests for TASK-018...")
    unittest.main(verbosity=2)