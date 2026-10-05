import { useState, useEffect, useRef, useCallback } from 'react';
import { WebSocketEnvelope } from '../types';
import { useAuth } from './useAuth';

export type WSConnectionStatus = 'CONNECTING' | 'CONNECTED' | 'DISCONNECTED' | 'RECONNECTING';

type EventCallback = (envelope: WebSocketEnvelope) => void;

export const useWebSocket = () => {
  const { token } = useAuth();
  const [status, setStatus] = useState<WSConnectionStatus>('DISCONNECTED');
  const [lastEvent, setLastEvent] = useState<WebSocketEnvelope | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const listenersRef = useRef<Map<string, Set<EventCallback>>>(new Map());
  const reconnectTimeoutRef = useRef<any | null>(null);
  const pingIntervalRef = useRef<any | null>(null);

  const subscribe = useCallback((eventType: string, callback: EventCallback) => {
    if (!listenersRef.current.has(eventType)) {
      listenersRef.current.set(eventType, new Set());
    }
    listenersRef.current.get(eventType)!.add(callback);

    return () => {
      listenersRef.current.get(eventType)?.delete(callback);
    };
  }, []);

  const connect = useCallback(() => {
    if (!token) {
      setStatus('DISCONNECTED');
      return;
    }

    if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
      return;
    }

    setStatus('CONNECTING');
    const getWsUrl = (): string => {
      const explicitWs = import.meta.env.VITE_WS_URL;
      if (explicitWs) return explicitWs.trim();

      const apiUrl = import.meta.env.VITE_API_URL;
      if (apiUrl && apiUrl.startsWith('http')) {
        const cleanApi = apiUrl.trim().replace(/\/api\/?$/, '').replace(/\/+$/, '');
        const wsProto = cleanApi.startsWith('https:') ? 'wss:' : 'ws:';
        const wsHost = cleanApi.replace(/^https?:\/\//, '');
        return `${wsProto}//${wsHost}/ws/events`;
      }

      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const host = window.location.host;
      return `${protocol}//${host}/ws/events`;
    };

    const wsUrl = getWsUrl();

    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      // Send secure authentication frame
      ws.send(JSON.stringify({
        type: 'authenticate',
        token: token,
      }));

      // Setup heartbeat ping
      pingIntervalRef.current = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'ping' }));
        }
      }, 25000);
    };

    ws.onmessage = (event) => {
      try {
        const parsed = JSON.parse(event.data);

        if (parsed.type === 'connection_established') {
          setStatus('CONNECTED');
          return;
        }

        if (parsed.type === 'pong') {
          return;
        }

        if (parsed.event_type) {
          const envelope = parsed as WebSocketEnvelope;
          setLastEvent(envelope);

          // Dispatch to type-specific subscribers
          const handlers = listenersRef.current.get(envelope.event_type);
          if (handlers) {
            handlers.forEach((fn) => fn(envelope));
          }

          // Dispatch to catch-all subscribers ('*')
          const allHandlers = listenersRef.current.get('*');
          if (allHandlers) {
            allHandlers.forEach((fn) => fn(envelope));
          }
        }
      } catch (err) {
        console.error('Failed to parse WebSocket message:', err);
      }
    };

    ws.onclose = () => {
      setStatus('DISCONNECTED');
      if (pingIntervalRef.current) {
        clearInterval(pingIntervalRef.current);
      }

      // Schedule reconnection
      if (token) {
        setStatus('RECONNECTING');
        reconnectTimeoutRef.current = setTimeout(() => {
          connect();
        }, 3000);
      }
    };

    ws.onerror = (err) => {
      console.warn('WebSocket encountered error:', err);
    };
  }, [token]);

  useEffect(() => {
    connect();

    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (pingIntervalRef.current) {
        clearInterval(pingIntervalRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [connect]);

  return {
    status,
    isConnected: status === 'CONNECTED',
    lastEvent,
    subscribe,
    reconnect: connect,
  };
};
