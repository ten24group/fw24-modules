import type { AuthenticationResultType, ChallengeNameType, EmailMfaSettingsType } from "@aws-sdk/client-cognito-identity-provider";
import type { IAuthConstructConfig } from "@ten24group/fw24";
import type { DecodedIdToken } from "../services/cognito-service";


export type SignInResult = AuthenticationResultType | {
    session: string,
    challengeName: ChallengeNameType,
    challengeParameters?: Record<string, string>,
}

export type InitiateAuthResult = {
    session: string,
    challenges: ChallengeNameType[],
}

export type SignUpOptions = {
    username: string;
    password: string;
    email?: string;  // Optional email
    autoSignIn?: boolean;  // Optional parameter to automatically sign in after signup
    [key: string]: any;  // Allow arbitrary string properties
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

export type MfaMethod = 'EMAIL' | 'SMS' | 'SOFTWARE_TOKEN';

export type UserMfaPreferenceOptions = {
    enabledMethods: MfaMethod[];
    preferredMethod?: MfaMethod;
}

export type AdminMfaSettings = {
    username: string;
    enabledMethods: MfaMethod[];
    preferredMethod?: MfaMethod;
}

export type UserDetails = {
    username: string;
    email?: string;
    enabled?: boolean;
    userStatus?: string;
    attributes?: Array<{ Name: string, Value: string }>;
}

export interface IAuthService {
    getUser(usernameOrEmail: string): Promise<UserDetails>;
    signup(options: SignUpOptions): Promise<SignInResult | void>;
    signin(username: string, password: string): Promise<SignInResult>;
    signout(accessToken: string): Promise<void>;
    verify(username: string, code: string): Promise<void>;
    verifyUserAttribute(accessToken: string, attributeName: string, code: string): Promise<void>;
    getUserAttributeVerificationCode(accessToken: string, attributeName: string): Promise<void>;
    resendVerificationCode(username: string): Promise<void>;
    getCredentials(idToken: string): Promise<any>;
    verifyIdToken(idToken: string): Promise<DecodedIdToken>;
    changePassword(accessToken: string, oldPassword: string, newPassword: string): Promise<void>;
    forgotPassword(username: string): Promise<void>;
    confirmForgotPassword(username: string, code: string, newPassword: string): Promise<void>;
    getLoginOptions(username: string): Promise<InitiateAuthResult>;
    initiateOtpAuth(username: string, session: string): Promise<SignInResult>;
    respondToOtpChallenge(username: string, session: string, code: string): Promise<SignInResult>;
    refreshToken(refreshToken: string): Promise<SignInResult>;

    // Social sign-in methods
    initiateSocialSignIn(provider: SocialProvider, redirectUri: string): Promise<string>;
    completeSocialSignIn(provider: SocialProvider, code: string, redirectUri: string): Promise<SocialSignInResult>;
    linkSocialProvider(accessToken: string, provider: SocialProvider, code: string, redirectUri: string): Promise<void>;
    unlinkSocialProvider(accessToken: string, provider: SocialProvider): Promise<void>;

    // User methods
    updateUserMfaPreference(accessToken: string, mfaPreference: UserMfaPreferenceOptions): Promise<void>;

    // Admin methods
    createUser(options: CreateUserOptions): Promise<void>;
    setPassword(username: string, password: string, forceChangePassword?: boolean): Promise<void>
    resetPassword(username: string): Promise<void>
    setUserGroups(username: string, newGroups: string[]): Promise<void>;
    updateUserAttributes(options: UpdateUserAttributeOptions): Promise<void>;
    addUserToGroup(username: string, groupName: string): Promise<void>;
    getUserGroupNames(username: string): Promise<Array<string>>;
    removeUserFromGroup(username: string, groupName: string): Promise<void>;
    setUserMfaSettings(settings: AdminMfaSettings): Promise<void>;
    getSocialSignInConfig(redirectUri: string): Promise<SocialSignInConfigs>;
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

    getUser(usernameOrEmail: string): Promise<UserDetails>;

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
    autoVerifyUser?: boolean
}

export type SocialProvider = 'Google' | 'Facebook';

export type SocialSignInConfig = {
    authorizationUrl: string;
    clientId: string;
    redirectUri: string;
    grantType: string;
}

export type SocialSignInConfigs = {
    [key in SocialProvider]?: SocialSignInConfig;
}

export type SocialSignInResult = SignInResult & {
    isNewUser?: boolean;
    provider?: SocialProvider;
}