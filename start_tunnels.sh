#!/bin/bash

# Cloudflared Tunnel Automation Script

CLOUDFLARED_BIN="./cloudflared"

# 1. Check if cloudflared exists, download if not
if [ ! -f "$CLOUDFLARED_BIN" ]; then
    echo "☁️  'cloudflared' binary not found. Downloading..."
    curl -L --output cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
    chmod +x cloudflared
    echo "✅ Download complete."
else
    echo "✅ 'cloudflared' binary found."
fi

# Cleanup old tunnels
echo "🧹 Cleaning up old tunnels..."
pkill -f "$CLOUDFLARED_BIN tunnel" || true

echo "===================================================="
echo "🌐 Starting Tunnels..."
echo "NOTE: Quick Tunnels generate RANDOM URLs every time."
echo "You MUST update 'deploy.sh' and 'client' config if these change!"
echo "===================================================="

# 2. Start Backend Tunnel in background
echo "🚀 Exposing BACKEND (Port 3000)..."
# We use nohup to keep it running, and pipe output to a log file so we can find the URL
nohup $CLOUDFLARED_BIN tunnel --url http://localhost:3000 > backend_tunnel.log 2>&1 &
BACKEND_PID=$!
echo "   -> Backend Tunnel PID: $BACKEND_PID"

# 3. Start Frontend Tunnel in background
echo "🚀 Exposing FRONTEND (Port 5173)..."
nohup $CLOUDFLARED_BIN tunnel --url http://localhost:5173 > frontend_tunnel.log 2>&1 &
FRONTEND_PID=$!
echo "   -> Frontend Tunnel PID: $FRONTEND_PID"

echo "===================================================="
echo "⏳ Waiting for tunnels to initialize (this may take a moment)..."

# Wait loop
MAX_RETRIES=30
FOUND_URLS=false

for i in $(seq 1 $MAX_RETRIES); do
    if grep -q -a 'https://.*\.trycloudflare.com' backend_tunnel.log && grep -q -a 'https://.*\.trycloudflare.com' frontend_tunnel.log; then
        FOUND_URLS=true
        break
    fi
    sleep 2
    echo -n "."
done
echo ""

if [ "$FOUND_URLS" = true ]; then
    echo "✅ Tunnels initialized successfully!"
else
    echo "⚠️  Timed out waiting for tunnel URLs or connection failed."
    echo "Check backend_tunnel.log and frontend_tunnel.log for details."
fi

echo "===================================================="
echo "🔗 YOUR PUBLIC URLs:"
echo "===================================================="

# Extract URLs from logs
echo "👉 BACKEND URL:"
grep -a -o 'https://.*\.trycloudflare.com' backend_tunnel.log | head -n 1

echo ""
echo "👉 FRONTEND URL:"
grep -a -o 'https://.*\.trycloudflare.com' frontend_tunnel.log | head -n 1

echo "===================================================="
echo "⚠️  ACTION REQUIRED:"
echo "1. The BACKEND URL is automatically detected by deploy.sh."
echo "2. Run './deploy.sh client' or './deploy.sh all' to update the frontend."
echo "===================================================="
echo "Press Ctrl+C to stop this script (it will likely exit, but tunnels run in background)."
echo "To kill tunnels later, run: pkill -f cloudflared"
