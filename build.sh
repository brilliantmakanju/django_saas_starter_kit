echo "🚀 Starting Render Build Process..."

# Install system dependencies
echo "🔧 Installing system dependencies..."
apt-get update && apt-get install -y graphviz graphviz-dev

# Install Python dependencies
echo "📦 Installing dependencies..."
python3.12 -m venv viper
source viper/bin/activate
python3.12 -m pip install --upgrade pip
python3.12 -m pip install -r requirements.txt

# Apply database migrations
echo "🛠 Applying database migrations..."
python3.12 manage.py migrate --noinput

# Collect static files
echo "🎨 Collecting static files..."
python3.12 manage.py collectstatic --noinput

# Start the server
echo "✅ Build process completed. Ready to deploy!"
