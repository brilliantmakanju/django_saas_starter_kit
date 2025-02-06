echo "🚀 Starting Render Build Process..."

# Install dependencies
echo "📦 Installing dependencies..."
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# Apply database migrations
echo "🛠 Applying database migrations..."
python manage.py migrate --noinput

# Collect static files
echo "🎨 Collecting static files..."
python manage.py collectstatic --noinput

# Start the server
echo "✅ Build process completed. Ready to deploy!"
