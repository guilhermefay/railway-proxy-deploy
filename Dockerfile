# Dockerfile para o proxy WebSocket
FROM node:20-alpine

WORKDIR /app

# Copiar apenas o necessário (arquivos já estão no diretório atual)
COPY realtimeProxy.ts ./realtimeProxy.ts
COPY package.json ./
COPY tsconfig.json ./

# Instalar dependências
RUN npm install

# Porta do proxy
ENV PORT=8080
ENV MODEL=gpt-4o-realtime-preview-2024-10-01

EXPOSE 8080

# Rodar com tsx diretamente
CMD ["npm", "start"]