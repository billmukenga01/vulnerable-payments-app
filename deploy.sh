#!/bin/bash

# Configuration
NETWORK_NAME="vulnerable-net"
# IMPORANT: Auto-fetch from log if available, otherwise use default
if [ -f backend_tunnel.log ]; then
    LOG_URL=$(grep -a -o 'https://.*\.trycloudflare.com' backend_tunnel.log | head -n 1)
else
    LOG_URL=""
fi
if [ ! -z "$LOG_URL" ]; then
    BACKEND_TUNNEL_URL="$LOG_URL/api"
    echo "🌍 Auto-detected Backend Tunnel: $BACKEND_TUNNEL_URL"
else
    # Fallback to hardcoded or localhost if you prefer
    BACKEND_TUNNEL_URL="http://localhost:3000/api" 
    echo "⚠️  Could not detect tunnel URL. Using fallback: $BACKEND_TUNNEL_URL"
    echo "💡 TIP: Run './start_tunnels.sh' first to generate public URLs!"
fi

# 1. Refresh Server
refresh_server() {
    echo "=================================="
    echo "♻️  Refreshing Server (Backend)..."
    echo "=================================="
    
    echo "🛑 Stopping old server..."
    docker rm -f server || true

    echo "🏗️  Building new image..."
    docker build -t vulnerable-server ./server

    echo "🚀 Starting container..."
    docker run -d \
      --name server \
      --cap-drop ALL \
      --security-opt=no-new-privileges \
      --security-opt seccomp=$(pwd)/seccomp_strict.json \
      --read-only \
      --tmpfs /tmp \
      --tmpfs /run \
      --tmpfs /home/appuser \
      --tmpfs /data:mode=1777 \
      --net $NETWORK_NAME \
      -p 3000:3000 \
      -e PORT=3000 \
      -e DATABASE_URL="file:/data/dev.db" \
      vulnerable-server
      
    echo "✅ Server is READY!"
}

# 2. Refresh Client
refresh_client() {
    echo "=================================="
    echo "♻️  Refreshing Client (Frontend)..."
    echo "=================================="

    echo "🛑 Stopping old client..."
    docker rm -f client || true

    echo "🏗️  Building new image (with API URL=$BACKEND_TUNNEL_URL)..."
    docker build \
        --build-arg VITE_API_BASE_URL="$BACKEND_TUNNEL_URL" \
        -t vulnerable-client ./client

    echo "🚀 Starting container..."
    # Note: We pass the backend URL so the frontend knows where to send requests
    docker run -d \
      --name client \
      --cap-drop ALL \
      --security-opt=no-new-privileges \
      --read-only \
      --tmpfs /tmp \
      --tmpfs /run \
      --tmpfs /home/appuser \
      --net $NETWORK_NAME \
      -p 5173:5173 \
      -e VITE_API_BASE_URL="$BACKEND_TUNNEL_URL" \
      vulnerable-client
      
    echo "✅ Client is READY!"
}

# Main Logic
if [ "$1" == "server" ]; then
    refresh_server
elif [ "$1" == "client" ]; then
    refresh_client
elif [ "$1" == "all" ]; then
    refresh_server
    refresh_client
else
    echo "Usage: ./deploy.sh [server | client | all]"
    echo ""
    echo "Examples:"
    echo "  ./deploy.sh server  # Updates only the backend"
    echo "  ./deploy.sh client  # Updates only the frontend"
    echo "  ./deploy.sh all     # Updates everything"
fi
