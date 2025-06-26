import pkceChallenge from 'pkce-challenge';
import config from '../config.json';
import { Tokens } from './api';

interface SocialProviderConfig {
  id: string;
  authorizeUrl: string;
  clientId: string;
  scope: string;
}

// Get typed providers list
const socialProviders = (config.features?.social?.providers as SocialProviderConfig[]) || [];

/**
 * Generate a PKCE code challenge and verifier pair.
 */
export function generatePkcePair(): { verifier: string; challenge: string } {
  const { code_verifier: verifier, code_challenge: challenge } = pkceChallenge();
  return { verifier, challenge };
}

/**
 * Redirect user to OAuth2 authorize endpoint (PKCE flow).
 */
export function redirectToAuthorize(): void {
  const pkce = generatePkcePair();
  sessionStorage.setItem('pkceVerifier', pkce.verifier);
  const redirectPath = config.features?.pkce?.redirectPath || '/callback';
  const redirectUri = encodeURIComponent(window.location.origin + redirectPath);
  const scope = encodeURIComponent(config.features?.pkce?.scope || 'openid profile email');
  const provider = socialProviders[0];
  if (!provider) {
    throw new Error('OAuth2 social provider not configured');
  }
  const { clientId, authorizeUrl } = provider;
  const authUrl = `${authorizeUrl}?response_type=code&client_id=${clientId}&redirect_uri=${redirectUri}&scope=${scope}&code_challenge=${pkce.challenge}&code_challenge_method=S256`;
  window.location.href = authUrl;
}

/**
 * Exchange authorization code for tokens (PKCE).
 */
export async function exchangeCode(code: string): Promise<Tokens> {
  const verifier = sessionStorage.getItem('pkceVerifier');
  if (!verifier) throw new Error('PKCE verifier missing');
  const redirectPath = config.features?.pkce?.redirectPath || '/callback';
  const redirectUri = window.location.origin + redirectPath;
  const provider = socialProviders[0];
  if (!provider) {
    throw new Error('OAuth2 social provider not configured');
  }
  const { clientId } = provider;
  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    client_id: clientId,
    redirect_uri: redirectUri,
    code_verifier: verifier,
  });
  const res = await fetch(`${config.apiBaseUrl.replace(/\/$/,'')}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  });
  if (!res.ok) throw new Error('Token exchange failed');
  return res.json() as Promise<Tokens>;
} 