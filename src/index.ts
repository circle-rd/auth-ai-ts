export { AuthClient, createAuthClient } from "./client.js";
export type { AuthClientOptions } from "./client.js";
export { DEFAULT_SCOPES } from "./config.js";
export type { AuthClientConfig, ResolvedAuthClientConfig } from "./config.js";
export {
  getFeature,
  hasFeature,
  hasPermission,
  accessTokenClaimsSchema,
  hasRole,
  idTokenClaimsSchema,
  userInfoClaimsSchema,
} from "./claims.js";
export type {
  FeatureValue,
  IdTokenClaims,
  PermissionAction,
  UserInfoClaims,
} from "./claims.js";
export { AuthAiError, ERR } from "./errors.js";
export type {
  AuthAiErrorCode,
  AuthAiErrorDetails,
  AuthAiErrorOptions,
} from "./errors.js";
export {
  GrantManager,
  InProcessGrantLock,
  MemoryGrantStore,
  createGrantManager,
} from "./grants.js";
export type {
  AccessToken,
  GrantLock,
  GrantManagerOptions,
  GrantStore,
} from "./grants.js";
export type { IntrospectionResult } from "./introspection.js";
export type {
  ClientCredentialsOptions,
  LoginHandshake,
  LoginRequest,
  LoginResult,
  LogoutUrlOptions,
  RefreshOptions,
  StartLoginOptions,
  TokenSet,
  TokenTypeHint,
} from "./types.js";
export { AiClient, UserAi, createAiClient } from "./ai.js";
export type { AiClientOptions } from "./ai.js";
export { GatewayClient } from "./gateway.js";
export type {
  GatewayAgent,
  GatewayClientOptions,
  GatewayMcpServer,
  GatewayModel,
  GatewayTokens,
} from "./gateway.js";
export {
  isInsufficientCredit,
  isInsufficientCreditStatus,
  toGatewayError,
} from "./gateway-errors.js";
export { MICRO_PER_EUR, WalletClient, formatEuros } from "./wallet.js";
export type {
  ListTransactionsOptions,
  TopupOptions,
  WalletAccount,
  WalletSessionUsage,
  WalletSessionUsageOptions,
  WalletStats,
  WalletStatsOptions,
  WalletTransaction,
  WalletTransactionPage,
  WalletTransactionType,
} from "./wallet.js";
export { WALLET_SELF_SCOPE } from "./config.js";
