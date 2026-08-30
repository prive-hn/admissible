import { useCallback, useEffect, useRef, useState } from "react";
import type { CockpitState } from "../domain/types";
import { fetchState, subscribeState } from "../api/client";
import { makeDemoState } from "../domain/demoState";
import { deepFreeze } from "../domain/freeze";

export interface UseCockpitState {
  state: CockpitState;
  /** True once at least one live fetch or SSE frame has landed. */
  connected: boolean;
  /** Force an immediate refresh (after an intent POST). */
  refresh: () => void;
}

/**
 * Live cockpit state. Prefers SSE (`/api/state/stream`) and drops the polling
 * fallback as soon as the stream delivers a frame; if the stream is absent or
 * errors, polls GET /api/state every 1s instead. If the API is entirely
 * unreachable, surfaces the labeled demo state so the instrument still reads
 * truthfully offline ("Demo disconnected").
 */
export function useCockpitState(pollMs = 1000): UseCockpitState {
  const [state, setState] = useState<CockpitState>(() => deepFreeze(makeDemoState()));
  const [connected, setConnected] = useState(false);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);
  const unsub = useRef<(() => void) | null>(null);
  const alive = useRef(true);
  /** True once the stream has delivered a frame; polling then stands down. */
  const streaming = useRef(false);

  // Frozen before it reaches any view. A skin is in-bundle code and can reach
  // this object; freezing means it cannot rewrite a candidate into an accepted
  // artifact and have the honest view render the forgery.
  const applyLive = useCallback((s: CockpitState) => {
    if (!alive.current) return;
    setConnected(true);
    setState(deepFreeze({ ...s, connection: s.connection ?? "live" }));
  }, []);

  const poll = useCallback(async () => {
    try {
      const s = await fetchState();
      applyLive(s);
    } catch {
      if (!alive.current) return;
      setConnected((was) => {
        if (was) return was; // keep last good live snapshot on a transient blip
        setState((prev) =>
          prev.connection === "demo-disconnected" ? prev : deepFreeze(makeDemoState()),
        );
        return false;
      });
    }
  }, [applyLive]);

  const stopPolling = useCallback(() => {
    if (!timer.current) return;
    clearInterval(timer.current);
    timer.current = null;
  }, []);

  const startPolling = useCallback(() => {
    if (timer.current || streaming.current) return;
    void poll();
    timer.current = setInterval(() => void poll(), pollMs);
  }, [poll, pollMs]);

  const refresh = useCallback(() => {
    void poll();
  }, [poll]);

  useEffect(() => {
    alive.current = true;
    // Try SSE first; on any error, fall back to polling.
    unsub.current = subscribeState(
      (s) => {
        // The stream is authoritative once it delivers; the poll was only a
        // safety net for servers that do not expose it.
        streaming.current = true;
        stopPolling();
        applyLive(s);
      },
      () => {
        streaming.current = false;
        startPolling();
      },
    );
    // Safety net: if SSE never delivers a frame quickly, poll anyway.
    const kick = setTimeout(() => startPolling(), 50);
    return () => {
      alive.current = false;
      streaming.current = false;
      clearTimeout(kick);
      stopPolling();
      unsub.current?.();
    };
  }, [applyLive, startPolling, stopPolling]);

  return { state, connected, refresh };
}
