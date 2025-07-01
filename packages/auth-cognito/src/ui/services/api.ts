// @ts-nocheck: using JSON import for runtime-injected config
import { getUIConfig } from '../runtime-config';
import { CognitoMfaChallenge } from '../../const';


// Centralized API endpoint paths
export const API_PATHS = {
  signIn: '/signin',
  signUp: '/signup',
  confirmSignUp: '/verify',
  resendConfirmationCode: '/resendVerificationCode',
  forgotPassword: '/forgotPassword',
  confirmForgotPassword: '/confirmForgotPassword',
  setNewPassword: '/setNewPassword',
  signOut: '/signout',
  refreshToken: '/refreshToken',
  respondToAuthChallenge: '/respondToAuthChallenge',
  initiateAuth: '/initiateAuth',
  initiateSocialSignIn: '/initiateSocialSignIn',
  completeSocialSignIn: '/completeSocialSignIn',
};

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
  // Determine base URL from runtime config
  const cfg = getUIConfig();
  const baseUrl = (import.meta.env.VITE_API_BASE_URL as string) || cfg.apiBaseUrl;
  const res = await fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = (await res.json()) as { message: string };
    throw new Error(err.message);
  }
  const text = await res.text();
  try {
      return JSON.parse(text) as T;
  } catch(e) {
      return text as unknown as T;
  }
}

// ===== API FUNCTIONS =====

// --- Core Auth ---
export function signIn(params: { username?: string; email?: string; password: string }): Promise<SignInResponse> {
  return callApi<SignInResponse>(API_PATHS.signIn, params);
}

export function signUp(params: SignUpParams): Promise<SignUpResponse> {
  return callApi<SignUpResponse>(API_PATHS.signUp, params);
}

export function confirmSignUp(identifier: string, code: string): Promise<void> {
  return callApi<void>(API_PATHS.confirmSignUp, { email: identifier, code });
}

export function resendConfirmationCode(identifier: string): Promise<void> {
  return callApi<void>(API_PATHS.resendConfirmationCode, { username: identifier });
}

export function forgotPassword(identifier: string): Promise<void> {
  return callApi<void>(API_PATHS.forgotPassword, { username: identifier });
}

export function confirmForgotPassword(identifier: string, code: string, newPassword: string): Promise<void> {
  return callApi<void>(API_PATHS.confirmForgotPassword, { username: identifier, code, newPassword });
}

export function setNewPassword(username: string, session: string, newPassword: string): Promise<SignInResponse> {
  return callApi<SignInResponse>(API_PATHS.setNewPassword, { username, session, newPassword });
}

export function signOut(accessToken: string): Promise<void> {
  return callApi<void>(API_PATHS.signOut, { accessToken });
}

export function refreshToken(refreshTokenValue: string): Promise<Tokens> {
  return callApi<Tokens>(API_PATHS.refreshToken, { refreshToken: refreshTokenValue });
}

// --- Generic Challenge Responder ---
function respondToAuthChallenge(username: string, session: string, challengeName: string, challengeResponses: Record<string, any>): Promise<SignInResponse> {
    return callApi<SignInResponse>(API_PATHS.respondToAuthChallenge, {
        username,
        session,
        challengeName,
        challengeResponses
    });
}

// --- Magic Link ---
export function sendMagicLink(email: string): Promise<Challenge> {
  return callApi<Challenge>(API_PATHS.initiateAuth, { username: email, authFlow: 'CUSTOM_AUTH' });
}

export function verifyMagicLink(username: string, session: string, code: string): Promise<SignInResponse> {
    return respondToAuthChallenge(username, session, 'CUSTOM_CHALLENGE', {
        USERNAME: username,
        ANSWER: code,
    });
}

// --- Enhanced MFA ---
export function selectMfaMethod(
  username: string,
  session: string,
  mfaMethod: CognitoMfaChallenge.SMS_MFA | CognitoMfaChallenge.SOFTWARE_TOKEN_MFA
): Promise<Challenge> {
  return callApi<Challenge>(API_PATHS.respondToAuthChallenge, {
    username,
    session,
    challengeName: CognitoMfaChallenge.SELECT_MFA_TYPE,
    challengeResponses: {
      ANSWER: mfaMethod,
    },
  });
}

export function respondToMfaChallenge(
  username: string,
  session: string,
  code: string,
  mfaType: CognitoMfaChallenge.SMS_MFA | CognitoMfaChallenge.SOFTWARE_TOKEN_MFA
): Promise<SignInResponse> {
    return respondToAuthChallenge(username, session, mfaType, {
        USERNAME: username,
        [mfaType === CognitoMfaChallenge.SMS_MFA ? 'SMS_MFA_CODE' : 'SOFTWARE_TOKEN_MFA_CODE']: code,
    });
}

// --- Social Sign In ---
export async function initiateSocialSignIn(provider: string, redirectUri: string): Promise<void> {
  const { authorizationUrl } = await callApi<{ authorizationUrl: string }>(API_PATHS.initiateSocialSignIn, { provider, redirectUri });
  window.location.href = authorizationUrl;
}

export function completeSocialSignIn(provider: string, code: string, redirectUri: string): Promise<SignInResponse> {
  return callApi<SignInResponse>(API_PATHS.completeSocialSignIn, { provider, code, redirectUri });
} 