import { useCallback, useEffect, useRef, useState } from 'react';

export const SLOW_REQUEST_THRESHOLD_MS = 3000;

export interface SlowRequestResult {
  readonly run: <T>(task: () => Promise<T>) => Promise<T>;
  readonly isSlow: boolean;
  readonly elapsedSeconds: number;
}

/**
 * Wraps a single in-flight API request. Normal (fast) requests are untouched.
 * If a request has not settled after SLOW_REQUEST_THRESHOLD_MS, `isSlow` flips to
 * true and `elapsedSeconds` starts counting so the UI can show a waiting state.
 * The request is never cancelled or retried here: the caller keeps awaiting it and
 * surfaces its real result or error exactly as before.
 */
export function useSlowRequest(): SlowRequestResult {
  const [isSlow, setIsSlow] = useState(false);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const tokenRef = useRef(0);
  const startRef = useRef<number | null>(null);
  const slowTimerRef = useRef<number | null>(null);
  const tickTimerRef = useRef<number | null>(null);

  const clearTimers = useCallback(() => {
    if (slowTimerRef.current !== null) {
      window.clearTimeout(slowTimerRef.current);
      slowTimerRef.current = null;
    }
    if (tickTimerRef.current !== null) {
      window.clearInterval(tickTimerRef.current);
      tickTimerRef.current = null;
    }
  }, []);

  const run = useCallback(
    async <T,>(task: () => Promise<T>): Promise<T> => {
      const token = tokenRef.current + 1;
      tokenRef.current = token;
      clearTimers();

      const startedAt = Date.now();
      startRef.current = startedAt;
      setIsSlow(false);
      setElapsedSeconds(0);

      slowTimerRef.current = window.setTimeout(() => {
        if (tokenRef.current !== token) return;
        setIsSlow(true);
        setElapsedSeconds(Math.max(0, Math.floor((Date.now() - startedAt) / 1000)));
        tickTimerRef.current = window.setInterval(() => {
          if (tokenRef.current !== token) return;
          setElapsedSeconds(Math.max(0, Math.floor((Date.now() - startedAt) / 1000)));
        }, 1000);
      }, SLOW_REQUEST_THRESHOLD_MS);

      try {
        return await task();
      } finally {
        if (tokenRef.current === token) {
          clearTimers();
          setIsSlow(false);
          setElapsedSeconds(0);
          startRef.current = null;
        }
      }
    },
    [clearTimers],
  );

  useEffect(() => clearTimers, [clearTimers]);

  return { run, isSlow, elapsedSeconds };
}