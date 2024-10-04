import { createToken } from "@ten24group/fw24";

export const AuthModuleClientDIToken = createToken('AuthModuleClient'); 
export const AuthModulePolicy_AllowCreateUserAuth = 'Policy:AllowCreateUserAuth';

export const AuthServiceDIToken = createToken('auth-cognito:IAuthService');