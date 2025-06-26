// @ts-nocheck: using JSON import for runtime-injected config
import config from '../config.json';

// Allow overriding API base URL in development via VITE_API_BASE_URL
const baseUrl = (import.meta.env.VITE_API_BASE_URL as string) || (config.apiBaseUrl as string);

// ===== TYPES =====
export interface Tokens {
  AccessToken: string;
  IdToken: string;
  RefreshToken: string;
  TokenType: string;
  ExpiresIn: number;
}
export interface Challenge {
  challengeName: string;
  session: string;
  challengeParameters?: Record<string, string>;
}
export type SignInResponse = Tokens | Challenge;

export interface SignUpParams {
  username?: string;
  email?: string;
  password: string;
  autoSignIn?: boolean;
  [key: string]: unknown;
}
export interface SignUpResponse {
  session?: string;
  UserConfirmed?: boolean;
  UserSub?: string;
  CodeDeliveryDetails?: {
    Destination: string;
    DeliveryMedium: string;
    AttributeName: string;
  };
}

// ===== HELPERS =====
async function callApi<T>(path: string, body: object): Promise<T> {
  const res = await fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = (await res.json()) as { message: string };
    throw new Error(err.message);
  }
  return res.json() as Promise<T>;
}

// ===== API FUNCTIONS =====
export function signIn(params: { username?: string; email?: string; password: string }): Promise<SignInResponse> {
  return callApi<SignInResponse>('/signin', params);
}

export function signUp(params: SignUpParams): Promise<SignUpResponse> {
  return callApi<SignUpResponse>('/signup', params);
}

export function confirmSignUp(identifier: string, code: string): Promise<void> {
  return callApi<void>('/verify', { username: identifier, code });
}

export function forgotPassword(identifier: string): Promise<void> {
  return callApi<void>('/forgotPassword', { username: identifier });
}

export function confirmForgotPassword(identifier: string, code: string, newPassword: string): Promise<void> {
  return callApi<void>('/confirmForgotPassword', { username: identifier, code, newPassword });
}

export function initiateAuth(username: string): Promise<{ session: string; challenges: string[] }> {
  return callApi(`/initiateAuth`, { username });
}

export function initiateOtpAuth(username: string, session: string): Promise<Challenge> {
  return callApi<Challenge>('/initiateOtpAuth', { username, session });
}

export function respondToOtpChallenge(username: string, session: string, code: string): Promise<SignInResponse> {
  return callApi<SignInResponse>('/respondToOtpChallenge', { username, session, code });
}

export function sendMagicLink(email: string): Promise<void> {
  return callApi<void>('/initiateAuth', { username: email, authFlow: 'CUSTOM_AUTH' });
}

export function verifyMagicLink(session: string, code: string): Promise<Tokens> {
  return callApi<Tokens>('/respondToAuthChallenge', { session, code, challengeName: 'CUSTOM_CHALLENGE' });
}

export function initiateSmsMfa(username: string, session: string): Promise<Challenge> {
  return callApi<Challenge>('/initiateAuth', { username, session, authFlow: 'USER_PASSWORD_AUTH' });
}

export function initiateSoftwareTokenMfa(username: string, session: string): Promise<Challenge> {
  return callApi<Challenge>('/initiateAuth', { username, session, authFlow: 'USER_PASSWORD_AUTH' });
}

export function refreshToken(refreshToken: string): Promise<Tokens> {
  return callApi<Tokens>('/refreshToken', { refreshToken });
}

export function signOut(accessToken: string): Promise<void> {
  return callApi<void>('/signout', { accessToken });
}

// Redirect user to social provider OAuth2 authorization
export function socialSignIn(provider: string): void {
  // Redirect to the OAuth2 authorize endpoint with the provider and current URL
  const redirectUri = encodeURIComponent(window.location.href);
  window.location.href = `${baseUrl}/oauth2/authorize?identity_provider=${provider}&redirect_uri=${redirectUri}`;
} 