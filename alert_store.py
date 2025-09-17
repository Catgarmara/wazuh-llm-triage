#!/usr/bin/env python3
"""
Alert Store - Simple SQLite Storage for Alerts
Task 008: Extracted from security_analyzer.py

Simple alert storage with basic CRUD operations:
- save_alert(alert_data) - Save alert to SQLite
- get_alerts(limit=20) - Get recent alerts  
- get_alert_by_id(alert_id) - Get specific alert

No ORM, no models, no complex patterns - just basic SQLite operations.
"""

import sqlite3
import json
import datetime
import os


def _get_db_connection():
    """Get database connection with basic error handling"""
    try:
        conn = sqlite3.connect("alerts.db")
        return conn
    except sqlite3.Error as e:
        print(f"Database Error: Connection failed - {e}")
        return None


def _ensure_table_exists():
    """Create alerts table if it doesn't exist"""
    conn = _get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                alert_json TEXT NOT NULL,
                ai_response TEXT
            )
        """)
        conn.commit()
        conn.close()
        return True
    except sqlite3.Error as e:
        print(f"Database Error: Table creation failed - {e}")
        if conn:
            conn.close()
        return False


def save_alert(alert_data, ai_response=None):
    """
    Save alert to SQLite database
    
    Args:
        alert_data: Alert data (dict or string)
        ai_response: Optional AI analysis response
        
    Returns:
        Alert ID if successful, None if failed
    """
    # Ensure table exists
    if not _ensure_table_exists():
        return None
    
    conn = _get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor()
        
        # Prepare data for storage
        timestamp = datetime.datetime.now().isoformat()
        alert_json_str = json.dumps(alert_data) if isinstance(alert_data, dict) else str(alert_data)
        
        # Insert alert
        cursor.execute("""
            INSERT INTO alerts (timestamp, alert_json, ai_response)
            VALUES (?, ?, ?)
        """, (timestamp, alert_json_str, ai_response))
        
        alert_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return alert_id
        
    except sqlite3.Error as e:
        print(f"Database Error: Save failed - {e}")
        if conn:
            conn.close()
        return None


def get_alerts(limit=20):
    """
    Get recent alerts from database
    
    Args:
        limit: Maximum number of alerts to return (default 20)
        
    Returns:
        List of alert dictionaries, empty list if failed
    """
    conn = _get_db_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, timestamp, alert_json, ai_response
            FROM alerts
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        # Convert to dictionaries
        alerts = []
        for row in rows:
            alert = {
                "id": row[0],
                "timestamp": row[1],
                "ai_response": row[3]
            }
            
            # Parse JSON alert data
            try:
                alert["alert_data"] = json.loads(row[2])
            except json.JSONDecodeError:
                alert["alert_data"] = row[2]  # Keep as string if not valid JSON
            
            alerts.append(alert)
        
        return alerts
        
    except sqlite3.Error as e:
        print(f"Database Error: Get alerts failed - {e}")
        if conn:
            conn.close()
        return []


def get_alert_by_id(alert_id):
    """
    Get specific alert by ID
    
    Args:
        alert_id: Alert ID to retrieve
        
    Returns:
        Alert dictionary if found, None if not found or error
    """
    conn = _get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, timestamp, alert_json, ai_response
            FROM alerts
            WHERE id = ?
        """, (alert_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        # Build alert dictionary
        alert = {
            "id": row[0],
            "timestamp": row[1], 
            "ai_response": row[3]
        }
        
        # Parse JSON alert data
        try:
            alert["alert_data"] = json.loads(row[2])
        except json.JSONDecodeError:
            alert["alert_data"] = row[2]  # Keep as string if not valid JSON
        
        return alert
        
    except sqlite3.Error as e:
        print(f"Database Error: Get alert by ID failed - {e}")
        if conn:
            conn.close()
        return None


def update_alert(alert_id, ai_response):
    """
    Update existing alert with AI analysis
    
    Args:
        alert_id: Alert ID to update
        ai_response: AI analysis response to save
        
    Returns:
        True if successful, False if failed
    """
    conn = _get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE alerts SET ai_response = ? WHERE id = ?",
            (ai_response, alert_id)
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.Error as e:
        print(f"Database Error: Update failed - {e}")
        if conn:
            conn.close()
        return False


if __name__ == "__main__":
    """Simple test of alert storage functions"""
    print("Testing alert_store.py...")
    
    # Test save_alert
    test_alert = {
        "alert_id": "TEST_001",
        "event_type": "test_event",
        "timestamp": datetime.datetime.now().isoformat()
    }
    
    print("Saving test alert...")
    alert_id = save_alert(test_alert, "Test AI response")
    if alert_id:
        print(f"Alert saved with ID: {alert_id}")
        
        # Test get_alert_by_id
        print("Retrieving alert by ID...")
        retrieved = get_alert_by_id(alert_id)
        if retrieved:
            print(f"Retrieved alert: {retrieved['alert_data']['alert_id']}")
        
        # Test get_alerts
        print("Getting recent alerts...")
        alerts = get_alerts(5)
        print(f"Found {len(alerts)} alerts")
        
    else:
        print("Failed to save test alert")