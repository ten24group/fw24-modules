import { IAuthConstructConfig } from "@ten24group/fw24";

export interface IAuthService {
    signup(email: string, password: string): Promise<void>;
    signin(email: string, password: string): Promise<any>;
    signout(accessToken: string): Promise<void>;
    verify(email: string, code: string): Promise<void>;
    changePassword(accessToken: string, oldPassword: string, newPassword: string): Promise<void>;
    forgotPassword(email: string): Promise<void>;
    confirmForgotPassword(email: string, code: string, newPassword: string): Promise<void>;
    addUserToGroup(email: string, groupName: string): Promise<void>;
    getCredentials(idToken: string): Promise<any>;
}


export interface IAuthModuleConfig extends IAuthConstructConfig {
    
}