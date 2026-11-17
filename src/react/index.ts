import {
  createContext,
  createElement,
  useContext,
  useEffect,
  useMemo,
  useSyncExternalStore,
} from "react";
import type { ReactNode } from "react";
import { createBrowserAuth } from "../browser/client.js";
import type { BrowserAuth, WalletView } from "../browser/client.js";
import { createAuthStore, createResourceStore } from "../browser/store.js";
import type {
  AuthState,
  AuthStore,
  ResourceOptions,
  ResourceState,
} from "../browser/store.js";
import { getFeature, hasFeature, hasPermission, hasRole } from "../claims.js";
import type { FeatureValue, PermissionAction } from "../claims.js";
import type { GatewayModel } from "../gateway.js";
import type { SessionUser } from "../session-user.js";
import type { WalletStats } from "../wallet.js";

interface AuthContextValue {
  readonly auth: BrowserAuth;
  readonly store: AuthStore;
}

const AuthContext = createContext<AuthContextValue | null>(null);

function useAuthContext(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error("Wrap the application in <AuthProvider>");
  return context;
}

export interface AuthProviderProps {
  /** Defaults to a client on `basePath`. */
  readonly auth?: BrowserAuth;
  readonly basePath?: string;
  /** Re-reads the session when the tab becomes visible again. */
  readonly refreshOnFocus?: boolean;
  readonly children?: ReactNode;
}

export function AuthProvider(props: AuthProviderProps): ReactNode {
  const { auth: provided, basePath, refreshOnFocus = true, children } = props;
  const value = useMemo<AuthContextValue>(() => {
    const auth = provided ?? createBrowserAuth(basePath ? { basePath } : {});
    return { auth, store: createAuthStore(auth) };
  }, [provided, basePath]);

  useEffect(() => {
    void value.store.refresh();
    if (!refreshOnFocus) return undefined;
    const onVisible = (): void => {
      if (document.visibilityState === "visible") void value.store.refresh();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => document.removeEventListener("visibilitychange", onVisible);
  }, [value, refreshOnFocus]);

  return createElement(AuthContext.Provider, { value }, children);
}

export interface UseAuthResult extends AuthState {
  readonly login: (next?: string) => void;
  readonly logout: () => Promise<void>;
  readonly refresh: () => Promise<void>;
}

export function useAuth(): UseAuthResult {
  const { auth, store } = useAuthContext();
  const state = useSyncExternalStore(
    store.state.subscribe,
    store.state.get,
    store.state.get,
  );
  return useMemo(
    () => ({
      ...state,
      login: (next) => auth.login(next),
      logout: () => auth.logout(),
      refresh: () => store.refresh(),
    }),
    [state, auth, store],
  );
}

/** The signed-in user, or null while loading and when signed out. */
export function useUser(): SessionUser | null {
  return useAuth().user;
}

export interface Entitlements {
  hasRole(role: string): boolean;
  hasPermission(resource: string, action?: PermissionAction): boolean;
  hasFeature(key: string): boolean;
  getFeature(key: string): FeatureValue | undefined;
}

/** Entitlement checks for the current user: all false when signed out. */
export function useEntitlements(): Entitlements {
  const user = useUser();
  return useMemo(() => {
    const claims = user ?? {};
    return {
      hasRole: (role) => hasRole(claims, role),
      hasPermission: (resource, action) =>
        hasPermission(claims, resource, action),
      hasFeature: (key) => hasFeature(claims, key),
      getFeature: (key) => getFeature(claims, key),
    };
  }, [user]);
}

export interface UseResourceResult<T> extends ResourceState<T> {
  readonly refresh: () => Promise<void>;
}

function useResource<T>(
  load: () => Promise<T>,
  options: ResourceOptions,
  deps: readonly unknown[],
): UseResourceResult<T> {
  const { store: authStore } = useAuthContext();
  const { pollIntervalMs } = options;
  const resource = useMemo(
    () =>
      createResourceStore(load, {
        ...(pollIntervalMs === undefined ? {} : { pollIntervalMs }),
        // A 401 means the session ended: let the auth state say so.
        onError: (error) => {
          if (error.code === "SES_001") void authStore.refresh();
        },
      }),
    // `load` is rebuilt on every render: its inputs are the deps.
    [authStore, pollIntervalMs, ...deps],
  );
  useEffect(() => resource.start(), [resource]);
  const state = useSyncExternalStore(
    resource.state.subscribe,
    resource.state.get,
    resource.state.get,
  );
  return useMemo(
    () => ({ ...state, refresh: resource.refresh }),
    [state, resource],
  );
}

export interface UseWalletOptions {
  /** Reload the balance on this interval; 15 s is plenty. */
  readonly pollIntervalMs?: number;
}

/** The user's credit; `data.canSpend` tells whether a paid action may start. */
export function useWallet(
  options: UseWalletOptions = {},
): UseResourceResult<WalletView> {
  const { auth } = useAuthContext();
  return useResource(() => auth.getWallet(), options, [auth]);
}

export function useWalletStats(days?: number): UseResourceResult<WalletStats> {
  const { auth } = useAuthContext();
  return useResource(() => auth.getWalletStats(days), {}, [auth, days]);
}

/** The models the user may call on the gateway. */
export function useModels(): UseResourceResult<GatewayModel[]> {
  const { auth } = useAuthContext();
  return useResource(() => auth.listModels(), {}, [auth]);
}
