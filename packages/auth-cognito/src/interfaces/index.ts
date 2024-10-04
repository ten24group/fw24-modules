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

export type CreateUserAuthenticationOptions = { 
    email: string, 
    password: string, 
    userId?: string, 
    groups?: string[]
}

export type AddUserToGroupOptions = {
    email: string, 
    group: string
}

export type SetUserGroupsOptions = {
    email: string, 
    groups?: string[]
}

export interface IAuthModuleClient {
    createUserAuth(options: CreateUserAuthenticationOptions): Promise<void>;

    addUserToGroup( options: AddUserToGroupOptions): Promise<void>;
    
    setUserGroups( options: SetUserGroupsOptions): Promise<void>;
}

export interface IAuthModuleConfig extends IAuthConstructConfig {
    
}