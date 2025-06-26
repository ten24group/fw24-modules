declare module 'pkce-challenge' {
  interface PkcePair {
    code_verifier: string;
    code_challenge: string;
  }
  function pkceChallenge(length?: number): PkcePair;
  export default pkceChallenge;
} 