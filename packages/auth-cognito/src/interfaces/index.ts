import { IAuthConstructConfig } from "@ten24group/fw24";

export interface IAuthService {
    signup(username: string, password: string): Promise<void>;
    signin(username: string, password: string): Promise<any>;
    signout(accessToken: string): Promise<void>;
    verify(username: string, code: string): Promise<void>;
    
    getCredentials(idToken: string): Promise<any>;
    changePassword(accessToken: string, oldPassword: string, newPassword: string): Promise<void>;
    forgotPassword(username: string): Promise<void>;
    confirmForgotPassword(username: string, code: string, newPassword: string): Promise<void>;
   
    setUserGroups(username: string, newGroups: string[]): Promise<void>;
    addUserToGroup(username: string, groupName: string): Promise<void>;
    getUserGroupNames(username: string): Promise<Array<string>>;
    removeUserFromGroup(username: string, groupName: string): Promise<void>;
}

export type CreateUserAuthenticationOptions = { 
    username: string, 
    password: string, 
    groups?: string[]
}

export type AddUserToGroupOptions = {
    username: string, 
    group: string
}

export type SetUserGroupsOptions = {
    username: string, 
    groups?: string[]
}

export interface IAuthModuleClient {
    createUserAuth(options: CreateUserAuthenticationOptions): Promise<void>;

    addUserToGroup( options: AddUserToGroupOptions): Promise<void>;
    
    setUserGroups( options: SetUserGroupsOptions): Promise<void>;
}

export interface IAuthModuleConfig extends IAuthConstructConfig {
    
}