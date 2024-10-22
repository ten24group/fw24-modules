import { createToken } from "@ten24group/fw24";

export const AuthModuleClientDIToken = createToken('AuthModuleClient'); 
export const AuthModulePolicy_AllowCreateUserAuth = 'Policy:AllowCreateUserAuth';

export const AuthServiceDIToken = createToken('auth-cognito:IAuthService');


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