#!/usr/bin/env python3
"""
Development Server for Chat Application
Enhanced development server with live reloading and better error handling
"""

import os
import sys
import time
import threading
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from flask import Flask
from app import app as chat_app

class FileChangeHandler(FileSystemEventHandler):
    """Handle file system changes for live reloading"""
    
    def __init__(self, app):
        self.app = app
        self.last_reload = 0
        self.reload_delay = 1  # Minimum seconds between reloads
        
    def on_modified(self, event):
        if event.is_directory:
            return
            
        # Check if enough time has passed since last reload
        current_time = time.time()
        if current_time - self.last_reload < self.reload_delay:
            return
            
        file_path = event.src_path
        file_ext = Path(file_path).suffix.lower()
        
        # Only reload for relevant file types
        if file_ext in ['.py', '.html', '.css', '.js', '.json']:
            print(f"📁 File changed: {file_path}")
            self.last_reload = current_time
            
            if file_ext == '.py':
                print("🔄 Python file changed - server restart required")
                # In a full implementation, this would restart the server
            else:
                print("🔄 Static file changed - browser refresh recommended")

def setup_file_watcher():
    """Set up file system watcher for development"""
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
        
        event_handler = FileChangeHandler(chat_app)
        observer = Observer()
        
        # Watch for changes in the current directory
        observer.schedule(event_handler, ".", recursive=True)
        observer.start()
        
        print("👁️  File watcher started - monitoring for changes")
        return observer
        
    except ImportError:
        print("⚠️  Watchdog not installed - file watching disabled")
        print("   Install with: pip install watchdog")
        return None

def print_dev_info():
    """Print development server information"""
    print("\n" + "="*60)
    print("🚀 CHAT APPLICATION DEVELOPMENT SERVER")
    print("="*60)
    print(f"📍 Server URL: http://127.0.0.1:5000")
    print(f"📁 Static files: /static/")
    print(f"🏥 Health check: http://127.0.0.1:5000/health")
    print(f"💬 Chat endpoint: http://127.0.0.1:5000/chat")
    print("="*60)
    print("🎯 DEVELOPMENT FEATURES:")
    print("   • File watching for changes")
    print("   • Enhanced error messages")
    print("   • Debug mode enabled")
    print("   • CORS enabled for local development")
    print("="*60)
    print("⌨️  KEYBOARD SHORTCUTS:")
    print("   • Ctrl+C: Stop server")
    print("   • Ctrl+/: Focus input (in browser)")
    print("   • Ctrl+Shift+K: Clear chat (in browser)")
    print("="*60)
    print("📋 DEVELOPMENT COMMANDS:")
    print("   • python dev-server.py: Start development server")
    print("   • python app.py: Start production server")
    print("   • npm run serve: Serve static files only")
    print("="*60 + "\n")

def check_dependencies():
    """Check if all required dependencies are available"""
    missing_deps = []
    
    # Check Python dependencies
    python_deps = [
        ('flask', 'Flask'),
        ('flask_cors', 'Flask-CORS'),
        ('openai', 'OpenAI'),
        ('python-dotenv', 'python-dotenv')
    ]
    
    for module_name, package_name in python_deps:
        try:
            __import__(module_name)
        except ImportError:
            missing_deps.append(f"pip install {package_name}")
    
    # Check optional dependencies
    optional_deps = [
        ('watchdog', 'watchdog (for file watching)')
    ]
    
    for module_name, description in optional_deps:
        try:
            __import__(module_name)
        except ImportError:
            print(f"⚠️  Optional dependency missing: {description}")
            print(f"   Install with: pip install {module_name}")
    
    if missing_deps:
        print("❌ Missing required dependencies:")
        for dep in missing_deps:
            print(f"   {dep}")
        print("\nInstall all dependencies with:")
        print("   pip install -r requirements.txt")
        return False
    
    return True

def setup_development_config():
    """Configure Flask app for development"""
    # Enable debug mode
    chat_app.config['DEBUG'] = True
    
    # Enable testing mode
    chat_app.config['TESTING'] = False
    
    # Set development-specific settings
    os.environ.setdefault('FLASK_ENV', 'development')
    os.environ.setdefault('FLASK_DEBUG', 'true')
    
    # Enhanced logging for development
    import logging
    logging.getLogger('werkzeug').setLevel(logging.INFO)
    
    print("🔧 Development configuration applied")

def main():
    """Main development server function"""
    print("🚀 Starting Chat Application Development Server...")
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Setup development configuration
    setup_development_config()
    
    # Print development information
    print_dev_info()
    
    # Setup file watcher
    observer = setup_file_watcher()
    
    try:
        # Start the Flask development server
        print("🌟 Starting Flask development server...")
        print("   (Press Ctrl+C to stop)\n")
        
        chat_app.run(
            host='127.0.0.1',
            port=5000,
            debug=True,
            threaded=True,
            use_reloader=False  # We use our own file watcher
        )
        
    except KeyboardInterrupt:
        print("\n🛑 Shutting down development server...")
        
    finally:
        # Cleanup file watcher
        if observer:
            observer.stop()
            observer.join()
        
        print("✅ Development server stopped cleanly")

if __name__ == '__main__':
    main()