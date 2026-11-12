"use client";

import { useEffect, useRef, useState } from "react";
import type { RealtimeEvent } from "@/types/realtime";

const SSE_URL = "/api/v1/realtime/stream";

export type RealtimeEventHandler = (event: RealtimeEvent) => void;

interface UseRealtimeEventsOptions {
  onEvent: RealtimeEventHandler;
  onReconnect?: () => void;
  enabled?: boolean;
}

export function useRealtimeEvents({ onEvent, onReconnect, enabled = true }: UseRealtimeEventsOptions): {
  connected: boolean;
} {
  const [connected, setConnected] = useState(false);
  const esRef = useRef<EventSource | null>(null);
  const onEventRef = useRef(onEvent);
  const onReconnectRef = useRef(onReconnect);

  useEffect(() => {
    onEventRef.current = onEvent;
  }, [onEvent]);

  useEffect(() => {
    onReconnectRef.current = onReconnect;
  }, [onReconnect]);

  useEffect(() => {
    if (!enabled) return;

    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let backoff = 1000;

    function connect() {
      const es = new EventSource(SSE_URL, { withCredentials: true });
      esRef.current = es;

      es.onopen = () => {
        setConnected(true);
        backoff = 1000;
        // Reconnect contract: caller must REST-refetch before processing new events
        onReconnectRef.current?.();
      };

      es.onmessage = (e) => {
        try {
          const event = JSON.parse(e.data) as RealtimeEvent;
          onEventRef.current(event);
        } catch {
          // Malformed event — ignore
        }
      };

      es.onerror = () => {
        setConnected(false);
        es.close();
        esRef.current = null;
        reconnectTimer = setTimeout(() => {
          backoff = Math.min(backoff * 2, 30000);
          connect();
        }, backoff);
      };
    }

    connect();

    return () => {
      if (reconnectTimer) clearTimeout(reconnectTimer);
      esRef.current?.close();
      esRef.current = null;
      setConnected(false);
    };
  }, [enabled]);

  return { connected };
}
