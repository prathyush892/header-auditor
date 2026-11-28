"use client";

/**
 * Who is signed in, for every client component.
 *
 * The provider owns the one API client of the page, so the CSRF token it
 * keeps in memory is shared by all components. On mount it asks the API
 * (`GET /auth/session`); there is no other source of truth, since the
 * session cookie is httpOnly and invisible to JavaScript.
 */
import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  API_PROXY_PREFIX,
  type ApiClient,
  createApiClient,
  type Credentials,
  describeError,
  type User,
} from "./api";

export type SessionState =
  | { readonly status: "loading" }
  | { readonly status: "anonymous" }
  | { readonly status: "authenticated"; readonly user: User }
  | { readonly status: "error"; readonly message: string };

export interface SessionContextValue {
  readonly state: SessionState;
  readonly api: ApiClient;
  readonly signIn: (credentials: Credentials) => Promise<User>;
  readonly register: (credentials: Credentials) => Promise<User>;
  readonly signOut: (options?: { readonly everywhere?: boolean }) => Promise<void>;
  readonly refresh: () => Promise<void>;
}

const SessionContext = createContext<SessionContextValue | null>(null);

export interface SessionProviderProps {
  readonly children: ReactNode;
  /** Defaults to the same-origin proxy. Tests and Storybook-like setups inject one. */
  readonly api?: ApiClient;
}

export function SessionProvider({ children, api: injected }: SessionProviderProps) {
  const [state, setState] = useState<SessionState>({ status: "loading" });
  const [api] = useState<ApiClient>(
    () =>
      injected ??
      createApiClient({
        baseUrl: API_PROXY_PREFIX,
        onUnauthorized: () => {
          setState({ status: "anonymous" });
        },
      }),
  );

  /** Ask the API who we are. Never throws: failures become the "error" state. */
  const fetchState = useCallback(
    async (signal?: AbortSignal): Promise<SessionState | null> => {
      try {
        const current = await api.session(signal === undefined ? {} : { signal });
        return current === null
          ? { status: "anonymous" }
          : { status: "authenticated", user: current.user };
      } catch (error) {
        // Unmounted (or StrictMode's dev double-mount): drop the result.
        if (signal?.aborted === true) return null;
        return { status: "error", message: describeError(error) };
      }
    },
    [api],
  );

  useEffect(() => {
    const controller = new AbortController();
    void fetchState(controller.signal).then((next) => {
      if (next !== null && !controller.signal.aborted) setState(next);
    });
    return () => {
      controller.abort();
    };
  }, [fetchState]);

  const value = useMemo<SessionContextValue>(
    () => ({
      state,
      api,
      async signIn(credentials) {
        const { user } = await api.login(credentials);
        setState({ status: "authenticated", user });
        return user;
      },
      async register(credentials) {
        const { user } = await api.register(credentials);
        setState({ status: "authenticated", user });
        return user;
      },
      async signOut(options = {}) {
        try {
          await (options.everywhere === true ? api.logoutAll() : api.logout());
        } finally {
          setState({ status: "anonymous" });
        }
      },
      async refresh() {
        setState({ status: "loading" });
        const next = await fetchState();
        if (next !== null) setState(next);
      },
    }),
    [api, fetchState, state],
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionContextValue {
  const value = useContext(SessionContext);
  if (value === null) throw new Error("useSession must be used inside <SessionProvider>");
  return value;
}
