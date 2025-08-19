#!/bin/bash

echo "🚀 Deploying to Railway..."
echo "📦 Current directory: $(pwd)"
echo "🔧 Git status:"
git status --short

echo ""
echo "📤 Pushing to GitHub..."
git add -A
git commit -m "chore: deploy update $(date +%Y-%m-%d_%H:%M:%S)" || echo "No changes to commit"
git push

echo ""
echo "🚂 Deploying to Railway..."
railway up --service pdc-realtime-proxy --detach

echo ""
echo "✅ Deploy initiated! Check the build logs URL above."
echo "🔍 To check deployment status:"
echo "   curl https://pdc-realtime-proxy-production.up.railway.app/"