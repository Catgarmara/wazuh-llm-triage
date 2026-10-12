#!/bin/bash

# Activate virtual environment and run Flask app
echo "Starting Flask web chat application..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Check if dependencies are installed
if ! python -c "import flask" 2>/dev/null; then
    echo "Installing dependencies..."
    pip install -r requirements.txt
fi

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "Creating .env file from template..."
    cp .env.example .env
    echo "Please edit .env and add your actual DeepSeek API key"
fi

# Run the Flask application
echo "Starting server at http://127.0.0.1:5000"
python app.py