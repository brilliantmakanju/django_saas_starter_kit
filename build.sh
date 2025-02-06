echo "🚀 Starting Render Build Process..."

# Create and activate the virtual environment
python3.12 -m venv viper
source viper/bin/activate

# Install system dependencies (if any required like Graphviz)
echo "🔧 Installing system dependencies..."
# (skip this if Graphviz installation is problematic or switch to a Docker approach)

# Install Python dependencies
echo "📦 Installing dependencies..."
python3.12 -m pip install --upgrade pip
python3.12 -m pip install -r requirements.txt

# Apply database migrations
echo "🛠 Applying database migrations..."
python3.12 manage.py migrate --noinput

# Collect static files
echo "🎨 Collecting static files..."
python3.12 manage.py collectstatic --noinput

echo "✅ Build process completed. Ready to deploy!"
