#!/bin/bash

# Deploy automatizado usando Railway Token

export RAILWAY_TOKEN="18fdfb36-6eac-41cf-8409-934e58a0a147"

echo "🚀 Iniciando deploy no Railway..."
echo ""

# Verificar se o Railway CLI está instalado
if ! command -v railway &> /dev/null; then
    echo "Instalando Railway CLI..."
    npm install -g @railway/cli
fi

# Login com token
echo "🔑 Autenticando com Railway..."
railway login --token "$RAILWAY_TOKEN"

# Criar projeto
echo "📦 Criando projeto..."
railway init -n pdc-realtime-proxy

# Deploy
echo "🚢 Fazendo deploy..."
railway up -d

# Configurar variável de ambiente
if [ ! -z "$OPENAI_API_KEY" ]; then
    echo "🔧 Configurando OPENAI_API_KEY..."
    railway variables set OPENAI_API_KEY="$OPENAI_API_KEY"
else
    echo "⚠️  OPENAI_API_KEY não encontrada. Configure manualmente no Railway Dashboard."
fi

# Gerar domínio
echo "🌐 Gerando domínio público..."
railway domain

echo ""
echo "✅ Deploy concluído!"
echo ""
echo "📝 Próximos passos:"
echo "1. Copie a URL do domínio gerado acima"
echo "2. Atualize seu .env.local:"
echo "   NEXT_PUBLIC_REALTIME_PROXY_URL=wss://[SEU_DOMINIO].up.railway.app"
echo ""
echo "Para ver logs: railway logs"
echo "Para abrir dashboard: railway open"