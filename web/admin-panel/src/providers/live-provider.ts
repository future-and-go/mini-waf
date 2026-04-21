import type { LiveProvider, LiveEvent } from "@refinedev/core";
import { tokenStorage } from "../utils/axios";

// Real-time channel multiplexer over a single WebSocket to /ws/events.
//
// The Rust gateway accepts a Sec-WebSocket-Protocol of `bearer.<jwt>` for
// auth (browsers don't allow custom headers on WS). Each Refine channel
// subscribes to the same socket and receives every message; subscribers
// filter by their own logic. This is sufficient for current waf-api which
// only emits one event stream — if the backend later partitions by topic,
// the dispatch can fan out by `msg.channel`.
//
// Reconnect strategy: passive 5 s backoff. No exponential backoff because
// the LAN/loopback latency is sub-ms; aggressive reconnect is fine.

type Subscriber = (event: LiveEvent) => void;

interface SubscriberRecord {
  channel: string;
  callback: Subscriber;
}

const subscribers = new Map<symbol, SubscriberRecord>();
let socket: WebSocket | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

const ensureSocket = (): void => {
  if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
    return;
  }
  const token = tokenStorage.get();
  if (!token) return;

  const proto = location.protocol === "https:" ? "wss" : "ws";
  socket = new WebSocket(
    `${proto}://${location.host}/ws/events`,
    [`bearer.${token}`],
  );

  socket.onmessage = (ev) => {
    let payload: unknown;
    try {
      payload = JSON.parse(ev.data);
    } catch {
      payload = { raw: ev.data };
    }
    // Wrap raw WS messages in Refine's LiveEvent envelope; per-subscriber
    // logic decides what to do with the payload.
    for (const sub of subscribers.values()) {
      const event: LiveEvent = {
        channel: sub.channel,
        type: "*",
        payload: payload as Record<string, unknown>,
        date: new Date(),
      };
      sub.callback(event);
    }
  };

  socket.onclose = () => {
    socket = null;
    if (subscribers.size > 0) {
      reconnectTimer = setTimeout(ensureSocket, 5000);
    }
  };

  socket.onerror = () => {
    socket?.close();
  };
};

export const liveProvider: LiveProvider = {
  subscribe: ({ channel, callback }) => {
    const id = Symbol(channel);
    subscribers.set(id, { channel, callback: callback as Subscriber });
    ensureSocket();
    return id;
  },

  unsubscribe: (subscription) => {
    subscribers.delete(subscription as symbol);
    if (subscribers.size === 0) {
      socket?.close();
      socket = null;
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
    }
  },

  publish: () => {
    // waf-api does not accept client-published events on this socket.
    // Refine's auto-publish on mutations is intentionally a no-op here;
    // server-pushed messages are the source of truth.
  },
};
