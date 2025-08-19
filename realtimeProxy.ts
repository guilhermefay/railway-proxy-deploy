import WebSocket, { WebSocketServer } from 'ws';
import http from 'http';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

// --- Configuração
const PORT = process.env.PORT ? parseInt(process.env.PORT) : 8080;
const MODEL = process.env.MODEL || 'gpt-4o-realtime-preview-2024-10-01';
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';
const REALTIME_TOKEN_SECRET = process.env.REALTIME_TOKEN_SECRET || '';

// Timeouts e limites
const AUTH_TIMEOUT_MS = 15000;
const IDLE_TIMEOUT_MS = 60000;
const MAX_JSON_BYTES = 512 * 1024;
const MAX_BINARY_BYTES = 20 * 1024 * 1024;

// Log inicial para debug
console.log('[RealtimeProxy] Iniciando servidor...');
console.log('[RealtimeProxy] Variáveis de ambiente:', {
  PORT: process.env.PORT,
  OPENAI_API_KEY: process.env.OPENAI_API_KEY ? '***configurada***' : 'NÃO CONFIGURADA',
  REALTIME_TOKEN_SECRET: process.env.REALTIME_TOKEN_SECRET ? '***configurada***' : 'NÃO CONFIGURADA'
});

// Validação inicial (aviso em vez de erro)
if (!OPENAI_API_KEY) {
  console.error('[RealtimeProxy] AVISO: OPENAI_API_KEY não configurada! O proxy não funcionará.');
}
if (!REALTIME_TOKEN_SECRET) {
  console.error('[RealtimeProxy] AVISO: REALTIME_TOKEN_SECRET não configurada! A autenticação falhará.');
}

// --- Logging
const log = {
  info: (connId: string, msg: string, extra?: any) => {
    console.log(`[${connId}] ${msg}`, extra || '');
  },
  warn: (connId: string, msg: string, extra?: any) => {
    console.warn(`[${connId}] ${msg}`, extra || '');
  },
  err: (connId: string, msg: string, extra?: any) => {
    console.error(`[${connId}] ${msg}`, extra || '');
  }
};

// --- Servidor
const server = http.createServer((req, res) => {
  // Health check endpoint
  if (req.method === 'GET' && req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ 
      status: 'WebSocket Proxy Server Running',
      timestamp: new Date().toISOString(),
      model: MODEL,
      port: PORT,
      auth: 'JWT'
    }));
    return;
  }
  
  // Outros endpoints retornam 404
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found - This is a WebSocket server\n');
});

const wss = new WebSocketServer({
  server,
  perMessageDeflate: false,
  maxPayload: Math.max(MAX_JSON_BYTES, MAX_BINARY_BYTES),
});

wss.on('connection', async (client, req) => {
  const connId = `${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
  log.info(connId, 'Nova conexão', { ip: req.socket.remoteAddress });

  let upstream: WebSocket | null = null;
  let authed = false;
  let closed = false;
  let lastActivity = Date.now();
  let authUsedOnce = false;

  const closeAll = (code = 1000, reason = 'bye') => {
    if (closed) return;
    closed = true;
    try { upstream?.close(code, reason); } catch {}
    try { client.close(code, reason); } catch {}
    log.info(connId, 'Fechando', { code, reason });
  };

  // Timeout de auth
  const authTimer = setTimeout(() => {
    if (!authed) {
      log.warn(connId, 'Timeout de autenticação');
      closeAll(1008, 'auth-timeout');
    }
  }, AUTH_TIMEOUT_MS);

  // Monitor de idle
  const idleInterval = setInterval(() => {
    if (Date.now() - lastActivity > IDLE_TIMEOUT_MS) {
      log.warn(connId, 'Conexão idle');
      closeAll(1001, 'idle-timeout');
    }
  }, 30000);

  // Cleanup
  const cleanup = () => {
    clearTimeout(authTimer);
    clearInterval(idleInterval);
  };

  client.on('message', async (data, isBinary) => {
    lastActivity = Date.now();
    
    // Primeira mensagem deve ser auth
    if (!authed) {
      if (isBinary) {
        return closeAll(1003, 'expected-json-auth');
      }

      const buf = data as Buffer;
      if (buf.length > MAX_JSON_BYTES) {
        return closeAll(1009, 'auth-msg-too-large');
      }

      let msg: any;
      try {
        msg = JSON.parse(buf.toString('utf8'));
      } catch {
        return closeAll(1003, 'invalid-json');
      }

      if (msg?.type !== 'auth' || !msg?.token) {
        return closeAll(1008, 'auth-required');
      }
      if (authUsedOnce) {
        return closeAll(1008, 'duplicate-auth');
      }
      authUsedOnce = true;

      // Debug do token recebido
      log.info(connId, 'Token recebido:', {
        tokenLength: msg.token.length,
        tokenFormat: msg.token.substring(0, 20) + '...',
        tokenParts: msg.token.split('.').length
      });

      // Validação do token JWT LOCAL
      try {
        if (!REALTIME_TOKEN_SECRET) {
          throw new Error('REALTIME_TOKEN_SECRET não configurada');
        }
        
        const payload = jwt.verify(msg.token, REALTIME_TOKEN_SECRET) as jwt.JwtPayload;
        
        // Verificar issuer manualmente
        if (payload.iss !== 'pedi-pro-flow') {
          log.warn(connId, 'Token com issuer inválido', { issuer: payload.iss });
          return closeAll(1008, 'invalid-issuer');
        }
        
        // Verificar scope
        if (payload.scope !== 'realtime') {
          log.warn(connId, 'Token com scope inválido', { scope: payload.scope });
          return closeAll(1008, 'invalid-scope');
        }
        
        log.info(connId, 'Token JWT válido', { 
          userId: payload.sub,
          email: payload.email,
          exp: new Date((payload.exp || 0) * 1000).toISOString()
        });
      } catch (err: any) {
        log.warn(connId, 'Token JWT inválido', { error: err.message });
        return closeAll(1008, 'invalid-token');
      }

      // Conecta ao Realtime OpenAI
      const wsUrl = `wss://api.openai.com/v1/realtime?model=${encodeURIComponent(MODEL)}`;

      log.info(connId, 'Conectando ao OpenAI…', { model: MODEL });
      upstream = new WebSocket(wsUrl, {
        headers: {
          'Authorization': `Bearer ${OPENAI_API_KEY}`,
          'OpenAI-Beta': 'realtime=v1',
          'X-Proxy-Conn-Id': connId,
        },
      });

      upstream.on('open', () => {
        authed = true;
        clearTimeout(authTimer);
        log.info(connId, 'Conectado ao OpenAI');
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify({ type: 'auth.success' }));
        }
      });

      upstream.on('message', (d) => {
        if (client.readyState !== WebSocket.OPEN) return;
        
        // Log mensagens importantes do OpenAI
        try {
          const msg = JSON.parse(d.toString());
          if (['session.created', 'session.updated', 'error'].includes(msg.type)) {
            log.info(connId, `OpenAI -> Cliente: ${msg.type}`);
          }
        } catch (e) {
          // É binário, ignora
        }
        
        // Repasse direto (server->client)
        client.send(d);
      });

      upstream.on('pong', () => { lastActivity = Date.now(); });

      upstream.on('close', (c, r) => {
        log.warn(connId, 'Upstream fechou', { code: c, reason: r?.toString() });
        if (client.readyState === WebSocket.OPEN) client.close(c, r.toString());
      });

      upstream.on('error', (e) => {
        log.err(connId, 'Erro no upstream', { e: String(e) });
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify({ type: 'proxy.error', message: 'upstream-error' }));
          client.close(1011, 'upstream-error');
        }
      });

      return;
    }

    // Mensagens após auth - filtros de segurança
    if (!upstream || upstream.readyState !== WebSocket.OPEN) {
      log.warn(connId, 'Upstream não disponível');
      return;
    }

    // Aplicar filtros apenas em mensagens JSON
    if (!isBinary) {
      const buf = data as Buffer;
      if (buf.length > MAX_JSON_BYTES) {
        log.warn(connId, 'Mensagem JSON muito grande', { size: buf.length });
        return;
      }

      try {
        const msg = JSON.parse(buf.toString('utf8'));
        
        // Whitelist de tipos permitidos do cliente
        const clientAllowedTypes = [
          'input_audio_buffer.append',
          'input_audio_buffer.commit',
          'input_audio_buffer.clear',
          'conversation.item.create',
          'response.create',
          'response.cancel',
          'session.update',
          'conversation.item.update',
          'conversation.item.truncate',
          'conversation.item.delete'
        ];

        if (!clientAllowedTypes.includes(msg.type)) {
          log.warn(connId, 'Tipo de mensagem não permitido', { type: msg.type });
          return;
        }
      } catch {
        // Se não for JSON válido, bloqueia
        log.warn(connId, 'Mensagem não-JSON do cliente');
        return;
      }
    } else {
      // Mensagens binárias - verificar tamanho
      if (data.length > MAX_BINARY_BYTES) {
        log.warn(connId, 'Mensagem binária muito grande', { size: data.length });
        return;
      }
    }

    // Repasse para upstream
    upstream.send(data);
  });

  client.on('pong', () => { lastActivity = Date.now(); });

  client.on('close', (code, reason) => {
    log.info(connId, 'Cliente fechou', { code, reason: reason?.toString() });
    closeAll(code, reason?.toString());
    cleanup();
  });

  client.on('error', (e) => {
    log.err(connId, 'Erro no cliente', { e: String(e) });
    closeAll(1011, 'client-error');
    cleanup();
  });

  // Ping periódico
  const pingInterval = setInterval(() => {
    if (client.readyState === WebSocket.OPEN) {
      client.ping();
    }
  }, 30000);

  client.on('close', () => clearInterval(pingInterval));
});

// Start server
server.listen(PORT, '0.0.0.0', () => {
  console.log(`[RealtimeProxy] ws://localhost:${PORT}`);
  console.log(`[RealtimeProxy] Model: ${MODEL}`);
  console.log(`[RealtimeProxy] Auth: JWT (local validation)`);
  console.log(`[RealtimeProxy] Token secret: ${REALTIME_TOKEN_SECRET ? 'Configured' : 'MISSING!'}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('[RealtimeProxy] SIGTERM recebido, fechando...');
  wss.close(() => {
    server.close(() => {
      console.log('[RealtimeProxy] Servidor fechado');
      process.exit(0);
    });
  });
});