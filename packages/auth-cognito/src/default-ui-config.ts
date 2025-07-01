import type { UIConfig } from './ui/types';

/**
 * Canonical default UI config values. Used by the CDK construct and the runtime loader.
 */
export const defaultUIConfig: UIConfig = {
  apiBaseUrl: '', // must be overridden via module config
  theme: {
    colors: {
      primary: '#007bff',
      accent: '#6c757d'
    },
    logoUrl: '',
    customCss: '',
    textColor: '#333',
    errorColor: 'red',
  },
  features: {
    signUp: {
      enabled: true
    },
    forgotPassword: {
      enabled: true
    },
    pkce: {
      enabled: true,
      redirectPath: '/callback',
      scope: ''
    },
    social: {
      enabled: false,
      providers: [],
      callbackPath: '/social/callback'
    },
    passwordless: {
      enabled: true,
      loginPath: '/passwordless',
      confirmPath: '/confirm'
    },
    mfa: {
      enabled: true,
      methods: [ 'SMS', 'TOTP', 'EMAIL' ]
    },
  },
  i18n: {
    enabled: true,
    defaultLocale: 'en',
    locales: [ 'en' ]
  },
}; 