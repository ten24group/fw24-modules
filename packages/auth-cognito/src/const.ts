export const AuthModuleClientDIToken = 'AuthModuleClient'; 
export const AuthModulePolicy_AllowCreateUserAuth = 'Policy:AllowCreateUserAuth';

export const AuthServiceDIToken = 'auth-cognito:IAuthService';


export const CUSTOM_MESSAGE_SIGN_UP = 'CUSTOM_MESSAGE_SIGN_UP';
export const CUSTOM_SUBJECT_SIGN_UP = 'CUSTOM_SUBJECT_SIGN_UP';

export const CUSTOM_MESSAGE_RESEND_CODE = 'CUSTOM_MESSAGE_RESEND_CODE';
export const CUSTOM_SUBJECT_RESEND_CODE = 'CUSTOM_SUBJECT_RESEND_CODE';

export const CUSTOM_MESSAGE_AUTHENTICATE = 'CUSTOM_MESSAGE_AUTHENTICATE';
export const CUSTOM_SUBJECT_AUTHENTICATE = 'CUSTOM_SUBJECT_AUTHENTICATE';

export const CUSTOM_MESSAGE_FORGOT_PASSWORD = 'CUSTOM_MESSAGE_FORGOT_PASSWORD';
export const CUSTOM_SUBJECT_FORGOT_PASSWORD = 'CUSTOM_SUBJECT_FORGOT_PASSWORD';

export const CUSTOM_MESSAGE_ADMIN_CREATE_USER = 'CUSTOM_MESSAGE_ADMIN_CREATE_USER';
export const CUSTOM_SUBJECT_ADMIN_CREATE_USER = 'CUSTOM_SUBJECT_ADMIN_CREATE_USER';

export const CUSTOM_MESSAGE_UPDATE_USER_ATTRIBUTE = 'CUSTOM_MESSAGE_UPDATE_USER_ATTRIBUTE';
export const CUSTOM_SUBJECT_UPDATE_USER_ATTRIBUTE = 'CUSTOM_SUBJECT_UPDATE_USER_ATTRIBUTE';

export const CUSTOM_MESSAGE_VERIFY_USER_ATTRIBUTE = 'CUSTOM_MESSAGE_VERIFY_USER_ATTRIBUTE';
export const CUSTOM_SUBJECT_VERIFY_USER_ATTRIBUTE = 'CUSTOM_SUBJECT_VERIFY_USER_ATTRIBUTE';

// MFA method constants for UI and mapping to Cognito challenges
export enum UIMfaMethod {
  SMS = 'SMS',
  TOTP = 'TOTP',
  EMAIL = 'EMAIL',
}

export enum CognitoMfaChallenge {
  SMS_MFA = 'SMS_MFA',
  SOFTWARE_TOKEN_MFA = 'SOFTWARE_TOKEN_MFA',
  SELECT_MFA_TYPE = 'SELECT_MFA_TYPE',
}

/**
 * Maps UI MFA methods to Cognito challenge names.
 */
export const UIMfaToCognitoMfaChallenge: Record<
  UIMfaMethod,
  CognitoMfaChallenge.SMS_MFA | CognitoMfaChallenge.SOFTWARE_TOKEN_MFA
> = {
  [UIMfaMethod.SMS]: CognitoMfaChallenge.SMS_MFA,
  [UIMfaMethod.TOTP]: CognitoMfaChallenge.SOFTWARE_TOKEN_MFA,
  [UIMfaMethod.EMAIL]: CognitoMfaChallenge.SMS_MFA, // default fallback
};

// Service-level MFA method identifiers
export type MfaMethod = 'SMS' | 'EMAIL' | 'SOFTWARE_TOKEN';

// Storage key constants
export const STORAGE_KEYS = {
  pkceVerifier: 'pkceVerifier',
  oauthProvider: 'oauth_provider',
};