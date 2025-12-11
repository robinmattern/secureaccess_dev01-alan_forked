#!/bin/bash

echo "🚀 Starting Web Application..."

# Read ports from _config.js
FRONTEND_PORT=54333   #55351
BACKEND_PORT=54383    #55351
if [ -f "client/c01_client-first-app/config/app.json" ]; then
    FRONTEND_PORT=$(grep -o '"frontend":[[:space:]]*[0-9]*' client/c01_client-first-app/config/app.json | grep -o '[0-9]*' || echo 54000)
    BACKEND_PORT=$(grep -o '"backend":[[:space:]]*[0-9]*' client/c01_client-first-app/config/app.json | grep -o '[0-9]*' || echo 54001)
fi

# Kill any existing server processes to free up ports
lsof -ti :$BACKEND_PORT | xargs kill -9 2>/dev/null || true
lsof -ti :$FRONTEND_PORT | xargs kill -9 2>/dev/null || true
pkill -f "node server.mjs" 2>/dev/null || true
pkill -f "npx serve" 2>/dev/null || true
sleep 2

# Start backend server
echo "🔧 Starting backend server..."
# cd server/s01_server-first-app

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
    echo "📦 Installing server dependencies..."
    npm install --silent --no-audit --no-fund
fi

npm start &
BACKEND_PID=$!

# Wait for backend to start
sleep 3
if ! kill -0 $BACKEND_PID 2>/dev/null; then
    echo "❌ Backend server failed to start"
    exit 1
fi
echo "✅ Backend server started"

# Start frontend client
cd ../../client/c01_client-first-app

echo "🔧 Starting frontend server..."
npx serve . -l $FRONTEND_PORT >/dev/null 2>&1 &
FRONTEND_PID=$!

# Wait for frontend to start
sleep 3
if kill -0 $FRONTEND_PID 2>/dev/null; then
    echo "✅ Frontend server started"
else
    echo "❌ Frontend server failed to start"
fi

echo ""
echo "✅ Application started successfully!"
echo "🔗 Frontend: http://localhost:$FRONTEND_PORT"
echo "🔗 Backend API: http://localhost:$BACKEND_PORT"
echo ""
echo "🌐 Opening browser..."
open http://localhost:$FRONTEND_PORT 2>/dev/null || true
echo ""
echo "Press Ctrl+C to stop both servers"

# Cleanup function
cleanup() {
    echo "Stopping servers..."
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null || true
    sleep 1
    lsof -ti :$BACKEND_PORT | xargs kill -9 2>/dev/null || true
    lsof -ti :$FRONTEND_PORT | xargs kill -9 2>/dev/null || true
    exit 0
}

# Set trap for cleanup
trap cleanup INT TERM EXIT

# Keep both servers running
while kill -0 $BACKEND_PID 2>/dev/null && kill -0 $FRONTEND_PID 2>/dev/null; do
    sleep 5
done

echo "One or both servers stopped unexpectedly"