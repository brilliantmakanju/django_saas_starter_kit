echo "🚀 Starting Render Build Process..."

# Install dependencies
echo "📦 Installing dependencies..."
python3.9 -m venv viper
source viper/bin/activate
python3.9 -m pip install --upgrade pip
python3.9 -m pip install -r requirements.txt


# Apply database migrations
echo "🛠 Applying database migrations..."
python3.9 manage.py migrate --noinput

# Collect static files
echo "🎨 Collecting static files..."
python3.9 manage.py collectstatic --noinput

# Start the server
echo "✅ Build process completed. Ready to deploy!"
