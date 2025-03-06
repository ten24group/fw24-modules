import type { AuthenticationResultType, ChallengeNameType, UserType } from "@aws-sdk/client-cognito-identity-provider";
import type { IAuthConstructConfig } from "@ten24group/fw24";


export type SignInResult = AuthenticationResultType | {
    challengeName: ChallengeNameType,
    challengeParameters?: Record<string, string>,
}

export type CreateUserOptions = {
    username: string,
    tempPassword: string,
    attributes?: Array<{ Name: string, Value: string }>
}

export type UpdateUserAttributeOptions = {
    username: string,
    attributes: Array<{ Name: string, Value: string }>
}

export interface IAuthService {
    signup(username: string, password: string): Promise<void>;
    signin(username: string, password: string): Promise<SignInResult>;
    signout(accessToken: string): Promise<void>;
    verify(username: string, code: string): Promise<void>;
    getCredentials(idToken: string): Promise<any>;
    changePassword(accessToken: string, oldPassword: string, newPassword: string): Promise<void>;
    forgotPassword(username: string): Promise<void>;
    confirmForgotPassword(username: string, code: string, newPassword: string): Promise<void>;

    getUserByUserSub(userSub: string): Promise<UserType | undefined>;

    // Admin methods
    createUser(options: CreateUserOptions): Promise<void>;
    setPassword(username: string, password: string, forceChangePassword?: boolean): Promise<void>
    resetPassword(username: string): Promise<void>
    setUserGroups(username: string, newGroups: string[]): Promise<void>;
    updateUserAttributes(options: UpdateUserAttributeOptions): Promise<void>;
    addUserToGroup(username: string, groupName: string): Promise<void>;
    getUserGroupNames(username: string): Promise<Array<string>>;
    removeUserFromGroup(username: string, groupName: string): Promise<void>;
}

export type CreateUserAuthenticationOptions = {
    username: string,
    password: string,
    groups?: string[],
    userAttributes?: Array<{
        Name: string,
        Value: string,
    }>;
    autoLogin?: boolean;
    autoVerifyEmail?: boolean;
    autoTriggerForgotPassword?: boolean;
}

export type SigninUserOptions = {
    username: string,
    password: string,
}

export type AddUserToGroupOptions = {
    group: string,
    username: string,
}

export type RemoveUserFromGroupOptions = {
    group: string,
    username: string,
}

export type SetUserGroupsOptions = {
    groups?: string[],
    username: string,
}

export type SetUserPasswordOptions = {
    username: string,
    password: string,
    forceChangePassword?: boolean
}

export type ResetUserPasswordOptions = {
    username: string,
}

export interface IAuthModuleClient {
    createUserAuth(options: CreateUserAuthenticationOptions): Promise<void | SignInResult>;

    signinUser(options: SigninUserOptions): Promise<SignInResult>;
    updateUserAttributes(options: UpdateUserAttributeOptions): Promise<void>;

    getUserByUserSub(UserSub: string): Promise<UserType | undefined>;

    addUserToGroup(options: AddUserToGroupOptions): Promise<void>;
    setUserGroups(options: SetUserGroupsOptions): Promise<void>;

    setUserPassword(options: SetUserPasswordOptions): Promise<void>;
    resetUserPassword(options: ResetUserPasswordOptions): Promise<void>;

}

export interface IAuthModuleConfig extends IAuthConstructConfig {
    customMessageTemplates?: {
        signup?: {
            subject: string,
            message: string,
        },
        adminCreateUser?: {
            subject: string,
            message: string,
        },
        resendCode?: {
            subject: string,
            message: string,
        },
        forgotPassword?: {
            subject: string,
            message: string,
        },
        updateUserAttribute?: {
            subject: string,
            message: string,
        },
        verifyUserAttribute?: {
            subject: string,
            message: string,
        },
        authentication?: {
            subject: string,
            message: string,
        },
    }
}