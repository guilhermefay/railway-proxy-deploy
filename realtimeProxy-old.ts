#!/usr/bin/env node
/**
 * Proxy WebSocket para OpenAI Realtime (hardened)
 * Execução: ts-node src/services/realtimeProxy.ts
 */

import http from 'http';
import { setTimeout as delay } from 'timers/promises';
import WebSocket, { WebSocketServer } from 'ws';
import crypto from 'crypto';

type Json = Record<string, any>;

const MODEL = process.env.REALTIME_MODEL || 'gpt-4o-realtime-preview-2024-10-01';
const TOKEN_VALIDATION_URL = process.env.TOKEN_VALIDATION_URL || 'http://localhost:3000/api/openai-realtime-token';
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const PORT = parseInt(process.env.PROXY_PORT || '8080', 10);

// Limites e timeouts
const CLIENT_AUTH_TIMEOUT_MS = 30_000;
const INACTIVITY_TIMEOUT_MS = 120_000;
const TOKEN_FETCH_TIMEOUT_MS = 7_000;
const MAX_JSON_BYTES = 256 * 1024;             // 256 KB por mensagem JSON
const MAX_BINARY_BYTES = 512 * 1024;           // 512 KB por chunk binário
const MAX_BUFFERED_BYTES = 2 * 1024 * 1024;    // 2 MB de backpressure

if (!OPENAI_API_KEY) {
  console.error('[Proxy] FATAL: OPENAI_API_KEY não configurada');
  process.exit(1);
}

// --- Utils de log
const now = () => new Date().toISOString();
const log = {
  info: (id: string, msg: string, extra?: Json) => console.log(JSON.stringify({ t: now(), lvl: 'info', id, msg, ...extra })),
  warn: (id: string, msg: string, extra?: Json) => console.warn(JSON.stringify({ t: now(), lvl: 'warn', id, msg, ...extra })),
  err:  (id: string, msg: string, extra?: Json) => console.error(JSON.stringify({ t: now(), lvl: 'error', id, msg, ...extra })),
};

// --- Whitelists
const ALLOWED_CLIENT_TYPES = new Set<string>([
  // principais eventos do Realtime
  'auth',                          // só primeira msg
  'session.update',
  'response.create',
  'response.cancel',
  'input_audio_buffer.append',
  'input_audio_buffer.commit',
  'input_audio_buffer.clear',
  'response.output_audio.delta',
  'response.output_audio.done',
  'input_image.append',            // se usar imagens
  'conversation.item.create',
  'conversation.item.truncate',
  'conversation.item.delete',
]);

const ALLOWED_SESSION_FIELDS = new Set<string>([
  'instructions',
  'voice',
  'input_audio_format',
  'output_audio_format',
  'input_audio_transcription',
  'turn_detection',
  'temperature',
  'modalities',
  // campos normalmente aceitos pelos endpoints Realtime
  'max_response_output_tokens',
  'tools',
]);

// --- Sanitização de session.update
function isSafeSessionUpdate(msg: Json): boolean {
  if (msg?.type !== 'session.update') return true;
  const s = msg.session ?? {};
  // impede chaves desconhecidas
  const keys = Object.keys(s);
  if (!keys.every(k => ALLOWED_SESSION_FIELDS.has(k))) return false;

  // opcional: validações de formato básico
  if (s.input_audio_transcription && typeof s.input_audio_transcription !== 'object') return false;
  if (s.modalities && !Array.isArray(s.modalities)) return false;

  return true;
}

// --- Checagens de tamanho
function withinJsonSizeLimit(buf: Buffer) {
  return buf.byteLength <= MAX_JSON_BYTES;
}
function withinBinarySizeLimit(buf: Buffer) {
  return buf.byteLength <= MAX_BINARY_BYTES;
}

// --- Fetch com timeout
async function fetchWithTimeout(url: string, init: RequestInit, ms: number): Promise<Response> {
  const ctrl = new AbortController();
  const to = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(to);
  }
}

// --- Servidor
const server = http.createServer((req, res) => {
  // Health check endpoint
  if (req.method === 'GET' && req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ 
      status: 'WebSocket Proxy Server Running',
      timestamp: new Date().toISOString(),
      model: MODEL,
      port: PORT
    }));
    return;
  }
  
  // Outros endpoints retornam 404
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found - This is a WebSocket server\n');
});

const wss = new WebSocketServer({
  server,
  perMessageDeflate: false, // já está off
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
      log.warn(connId, 'Auth timeout');
      closeAll(1008, 'auth-timeout');
    }
  }, CLIENT_AUTH_TIMEOUT_MS);

  // Inatividade geral (ping/pong)
  const inactivityInterval = setInterval(() => {
    if (Date.now() - lastActivity > INACTIVITY_TIMEOUT_MS) {
      log.warn(connId, 'Inatividade atingida');
      return closeAll(1001, 'idle-timeout');
    }
    try {
      if (client.readyState === WebSocket.OPEN) client.ping();
      if (upstream?.readyState === WebSocket.OPEN) upstream.ping();
    } catch (e) {
      log.err(connId, 'Erro ping', { e: String(e) });
    }
  }, Math.floor(INACTIVITY_TIMEOUT_MS / 2));

  client.on('pong', () => { lastActivity = Date.now(); });

  client.on('message', async (data, isBinary) => {
    lastActivity = Date.now();

    // Se ainda não autenticado, a primeira msg deve ser auth
    if (!authed) {
      if (isBinary) {
        log.warn(connId, 'Binário antes de auth');
        return closeAll(1008, 'auth-required');
      }
      // Limita tamanho para evitar DoS
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(data as any);
      if (!withinJsonSizeLimit(buf)) {
        log.warn(connId, 'JSON excede limite na auth');
        return closeAll(1009, 'payload-too-large');
      }

      let msg: Json;
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

      // Validação do token via POST (sem vazar em query)
      try {
        const r = await fetchWithTimeout(
          TOKEN_VALIDATION_URL,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: msg.token }),
          },
          TOKEN_FETCH_TIMEOUT_MS
        );

        const result = await r.json().catch(() => ({}));
        if (!r.ok || result?.valid !== true) {
          log.warn(connId, 'Token inválido', { status: r.status });
          return closeAll(1008, 'invalid-token');
        }
      } catch (e) {
        log.err(connId, 'Falha ao validar token', { e: String(e) });
        return closeAll(1011, 'token-validation-error');
      }

      // Conecta ao Realtime OpenAI
      const wsUrl = `wss://api.openai.com/v1/realtime?model=${encodeURIComponent(MODEL)}`;

      log.info(connId, 'Conectando ao OpenAI…', { model: MODEL });
      upstream = new WebSocket(wsUrl, {
        headers: {
          'Authorization': `Bearer ${OPENAI_API_KEY}`,
          'OpenAI-Beta': 'realtime=v1',
          // Cabeçalhos extras que às vezes ajudam na depuração
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
        // Repasse direto (server->client). Aqui não aplicamos filtros.
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

    // A partir daqui, autenticado: repassar client->upstream com filtros
    if (!upstream || upstream.readyState !== WebSocket.OPEN) {
      log.warn(connId, 'Upstream não pronto');
      return;
    }

    // Backpressure: se o buffer está alto, rejeita para não explodir memória
    if (upstream.bufferedAmount > MAX_BUFFERED_BYTES) {
      log.warn(connId, 'Backpressure alto (bufferedAmount)', { buffered: upstream.bufferedAmount });
      return; // drop – ou poderia enfileirar e soltar depois
    }

    if (isBinary) {
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(data as any);
      if (!withinBinarySizeLimit(buf)) {
        log.warn(connId, 'Binário excede limite');
        return closeAll(1009, 'payload-too-large');
      }
      // Só envia binário após commit/append fluxos, então aqui repassamos
      upstream.send(buf, { binary: true });
      return;
    }

    // JSON
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data as any);
    if (!withinJsonSizeLimit(buf)) {
      log.warn(connId, 'JSON excede limite');
      return closeAll(1009, 'payload-too-large');
    }

    let msg: Json;
    try {
      msg = JSON.parse(buf.toString('utf8'));
    } catch {
      return closeAll(1003, 'invalid-json');
    }

    // Whitelist de tipos
    if (!ALLOWED_CLIENT_TYPES.has(msg?.type)) {
      log.warn(connId, 'Tipo de mensagem não permitido', { type: msg?.type });
      return;
    }

    // Sanitização de session.update
    if (!isSafeSessionUpdate(msg)) {
      log.warn(connId, 'session.update bloqueado (campos inválidos)');
      return;
    }

    // Tudo certo, repassa
    upstream.send(JSON.stringify(msg));
  });

  client.on('close', (code, reason) => {
    log.info(connId, 'Cliente fechou', { code, reason: reason?.toString() });
    clearTimeout(authTimer);
    clearInterval(inactivityInterval);
    closeAll();
  });

  client.on('error', (e) => {
    log.err(connId, 'Erro cliente', { e: String(e) });
    clearTimeout(authTimer);
    clearInterval(inactivityInterval);
    closeAll();
  });
});

// Startup
server.listen(PORT, () => {
  console.log(`[RealtimeProxy] ws://localhost:${PORT}`);
  console.log(`[RealtimeProxy] Model: ${MODEL}`);
  console.log(`[RealtimeProxy] Token validation: ${TOKEN_VALIDATION_URL} (POST)`);
});

// Graceful shutdown
for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.on(sig, async () => {
    console.log(`[RealtimeProxy] Encerrando (${sig})…`);
    try {
      await new Promise<void>((res) => wss.close(() => res()));
      await new Promise<void>((res) => server.close(() => res()));
    } finally {
      process.exit(0);
    }
  });
}
