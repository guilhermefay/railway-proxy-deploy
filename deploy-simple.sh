#!/bin/bash

echo "🚀 Deploy Manual do Proxy WebSocket no Railway"
echo "============================================="
echo ""
echo "📝 Siga estes passos:"
echo ""
echo "1️⃣  Execute: railway login"
echo "    (Vai abrir o navegador para autenticação)"
echo ""
echo "2️⃣  Execute: railway init"
echo "    - Escolha: Create New Project"
echo "    - Nome: pdc-realtime-proxy"
echo ""
echo "3️⃣  Execute: railway up"
echo "    (Vai fazer o deploy dos arquivos)"
echo ""
echo "4️⃣  Execute: railway variables set OPENAI_API_KEY='$OPENAI_API_KEY'"
echo ""
echo "5️⃣  Execute: railway domain"
echo "    (Vai gerar a URL pública)"
echo ""
echo "6️⃣  Copie a URL e atualize .env.local:"
echo "    NEXT_PUBLIC_REALTIME_PROXY_URL=wss://[URL].up.railway.app"
echo ""
echo "Pressione Enter para começar..."
read

# Passo 1: Login
railway login