
import { createToken } from "@ten24group/fw24";

export const AuthModuleClientDIToken = createToken('AuthModuleClient'); 
export const AuthModulePolicy_AllowCreateUserAuth = 'Policy:AllowCreateUserAuth';

export type CreateUserAuthenticationOptions = { 
    email: string, 
    password: string, 
    userId?: string, 
    groups?: string[]
}

export interface IAuthModuleClient {
    createUserAuth(options: CreateUserAuthenticationOptions): Promise<void>;
}