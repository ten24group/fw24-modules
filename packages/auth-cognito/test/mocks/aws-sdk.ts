import { mockClient } from 'aws-sdk-client-mock';
import { 
    CognitoIdentityProviderClient,
    SignUpCommand,
    InitiateAuthCommand,
    ConfirmSignUpCommand,
    GlobalSignOutCommand,
    GetUserCommand,
    AdminAddUserToGroupCommand,
    AdminListGroupsForUserCommand,
    AdminRemoveUserFromGroupCommand,
    ChangePasswordCommand,
    ForgotPasswordCommand,
    ConfirmForgotPasswordCommand,
    ResendConfirmationCodeCommand,
    VerifyUserAttributeCommand,
    GetUserAttributeVerificationCodeCommand,
    SetUserMFAPreferenceCommand,
    AdminSetUserMFAPreferenceCommand,
    AdminCreateUserCommand,
    AdminSetUserPasswordCommand,
    AdminResetUserPasswordCommand,
    AdminUpdateUserAttributesCommand,
    RespondToAuthChallengeCommand,
    AdminLinkProviderForUserCommand,
    AdminDisableProviderForUserCommand
} from '@aws-sdk/client-cognito-identity-provider';
import { 
    CognitoIdentityClient,
    GetIdCommand,
    GetCredentialsForIdentityCommand 
} from '@aws-sdk/client-cognito-identity';

// Create mock clients
export const cognitoIdpMock = mockClient(CognitoIdentityProviderClient);
export const cognitoIdentityMock = mockClient(CognitoIdentityClient);

// Reset all mocks before each test
export const resetMocks = () => {
    cognitoIdpMock.reset();
    cognitoIdentityMock.reset();
};

// Helper function to mock successful sign-up
export const mockSuccessfulSignUp = () => {
    cognitoIdpMock.on(SignUpCommand).resolves({
        UserConfirmed: false,
        UserSub: 'test-user-sub'
    });
};

// Helper function to mock successful sign-in
export const mockSuccessfulSignIn = () => {
    cognitoIdpMock.on(InitiateAuthCommand).resolves({
        AuthenticationResult: {
            AccessToken: 'test-access-token',
            IdToken: 'test-id-token',
            RefreshToken: 'test-refresh-token',
            ExpiresIn: 3600,
            TokenType: 'Bearer'
        }
    });
};

// Helper function to mock successful verification
export const mockSuccessfulVerification = () => {
    cognitoIdpMock.on(ConfirmSignUpCommand).resolves({});
};

// Helper function to mock successful sign-out
export const mockSuccessfulSignOut = () => {
    cognitoIdpMock.on(GlobalSignOutCommand).resolves({});
};

// Helper function to mock successful user retrieval
export const mockSuccessfulGetUser = (username: string, email: string) => {
    cognitoIdpMock.on(GetUserCommand).resolves({
        Username: username,
        UserAttributes: [
            { Name: 'email', Value: email },
            { Name: 'email_verified', Value: 'true' }
        ]
    });
};

// Helper function to mock successful group operations
export const mockSuccessfulGroupOperations = () => {
    cognitoIdpMock.on(AdminAddUserToGroupCommand).resolves({});
    cognitoIdpMock.on(AdminRemoveUserFromGroupCommand).resolves({});
    cognitoIdpMock.on(AdminListGroupsForUserCommand).resolves({
        Groups: [
            { GroupName: 'admin' },
            { GroupName: 'user' }
        ]
    });
};

// Helper function to mock successful password operations
export const mockSuccessfulPasswordOperations = () => {
    cognitoIdpMock.on(ChangePasswordCommand).resolves({});
    cognitoIdpMock.on(ForgotPasswordCommand).resolves({});
    cognitoIdpMock.on(ConfirmForgotPasswordCommand).resolves({});
    cognitoIdpMock.on(AdminSetUserPasswordCommand).resolves({});
    cognitoIdpMock.on(AdminResetUserPasswordCommand).resolves({});
};

// Helper function to mock successful user attribute operations
export const mockSuccessfulAttributeOperations = () => {
    cognitoIdpMock.on(GetUserAttributeVerificationCodeCommand).resolves({});
    cognitoIdpMock.on(VerifyUserAttributeCommand).resolves({});
    cognitoIdpMock.on(ResendConfirmationCodeCommand).resolves({});
    cognitoIdpMock.on(AdminUpdateUserAttributesCommand).resolves({});
};

// Helper function to mock successful MFA operations
export const mockSuccessfulMfaOperations = () => {
    cognitoIdpMock.on(SetUserMFAPreferenceCommand).resolves({});
    cognitoIdpMock.on(AdminSetUserMFAPreferenceCommand).resolves({});
};

// Helper function to mock successful user creation
export const mockSuccessfulUserCreation = () => {
    cognitoIdpMock.on(AdminCreateUserCommand).resolves({
        User: {
            Username: 'testuser',
            Enabled: true,
            UserStatus: 'FORCE_CHANGE_PASSWORD'
        }
    });
};

// Helper function to mock successful OTP operations
export const mockSuccessfulOtpOperations = () => {
    cognitoIdpMock.on(InitiateAuthCommand).resolves({
        Session: 'test-session',
        AvailableChallenges: ['EMAIL_OTP']
    });
    cognitoIdpMock.on(RespondToAuthChallengeCommand).resolves({
        AuthenticationResult: {
            AccessToken: 'test-access-token',
            IdToken: 'test-id-token',
            RefreshToken: 'test-refresh-token',
            ExpiresIn: 3600,
            TokenType: 'Bearer'
        }
    });
};

// Helper function to mock successful social provider operations
export const mockSuccessfulSocialProviderOperations = () => {
    cognitoIdpMock.on(AdminLinkProviderForUserCommand).resolves({});
    cognitoIdpMock.on(AdminDisableProviderForUserCommand).resolves({});
};

// Helper function to mock successful credentials operations
export const mockSuccessfulCredentialsOperations = () => {
    cognitoIdentityMock.on(GetIdCommand).resolves({
        IdentityId: 'test-identity-id'
    });
    cognitoIdentityMock.on(GetCredentialsForIdentityCommand).resolves({
        Credentials: {
            AccessKeyId: 'test-access-key',
            SecretKey: 'test-secret-key',
            SessionToken: 'test-session-token',
            Expiration: new Date()
        }
    });
}; 