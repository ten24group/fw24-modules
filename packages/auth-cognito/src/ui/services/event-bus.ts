// src/ui/events.ts
export const Events = {
  WidgetReady: 'auth-widget-ready',
  LoginSuccess: 'auth-login-success',  // detail: { AccessToken, IdToken, … }
  LoginFailure: 'auth-login-failure',  // detail: { message: string }
  Logout: 'auth-logout',         // detail: none
  TokenRefreshed: 'auth-token-refreshed',// detail: { AccessToken, … }
  SignupSuccess: 'auth-signup-success', // detail: SignUpResponse
  SignupFailure: 'auth-signup-failure', // detail: { message: string }
  SocialStarted: 'auth-social-start',   // detail: { provider: 'Google'|'Facebook' }
  SocialComplete: 'auth-social-complete',// detail: SignInResponse
} as const;


/**
 * Dispatch a CustomEvent from the <auth-widget> host,
 * so any embedding page can listen on that element.
 */
export function emitEvent(eventName: string, detail?: any) {
  // find the custom element
  const el = document.querySelector('auth-widget');
  if (!el) return;
  el.dispatchEvent(new CustomEvent(eventName, {
    detail,
    bubbles: true,
    composed: true,
  }));
}