#!/bin/bash

# Exit on error
set -e

echo "🚀 Starting Render Build Process..."

# Install dependencies
echo "📦 Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Apply database migrations
echo "🛠 Applying database migrations..."
python manage.py migrate --noinput

# Collect static files
echo "🎨 Collecting static files..."
python manage.py collectstatic --noinput

# Start the server
echo "✅ Build process completed. Ready to deploy!"
