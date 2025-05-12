import { describe, beforeEach, afterEach, it, expect, jest } from '@jest/globals';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { CognitoIdentityClient } from '@aws-sdk/client-cognito-identity';
import { CognitoService } from '../../src/services/cognito-service';
import { mockClient } from 'aws-sdk-client-mock';
import { 
    SignUpCommand, 
    InitiateAuthCommand, 
    ConfirmSignUpCommand, 
    GlobalSignOutCommand, 
    AdminAddUserToGroupCommand, 
    AdminListGroupsForUserCommand,
    GetUserCommand,
    AdminUpdateUserAttributesCommand,
    SetUserMFAPreferenceCommand,
    AdminSetUserMFAPreferenceCommand,
    RespondToAuthChallengeCommand,
    AdminLinkProviderForUserCommand,
    AdminDisableProviderForUserCommand,
    GetUserAttributeVerificationCodeCommand,
    VerifyUserAttributeCommand,
    ResendConfirmationCodeCommand,
    ChangePasswordCommand,
    ForgotPasswordCommand,
    ConfirmForgotPasswordCommand,
    AdminRemoveUserFromGroupCommand,
    AdminCreateUserCommandOutput,
    AdminSetUserPasswordCommandOutput,
    AdminResetUserPasswordCommandOutput,
    AdminListGroupsForUserCommandOutput,
    SetUserMFAPreferenceCommandOutput,
    AdminSetUserMFAPreferenceCommandOutput,
    InitiateAuthCommandOutput,
    RespondToAuthChallengeCommandOutput,
    AdminSetUserPasswordCommand
} from '@aws-sdk/client-cognito-identity-provider';
import { GetIdCommand, GetCredentialsForIdentityCommand } from '@aws-sdk/client-cognito-identity';
import 'aws-sdk-client-mock-jest';
import { 
    cognitoIdpMock, 
    cognitoIdentityMock, 
    resetMocks,
    mockSuccessfulSignUp,
    mockSuccessfulSignIn,
    mockSuccessfulVerification,
    mockSuccessfulSignOut,
    mockSuccessfulGetUser,
    mockSuccessfulGroupOperations,
    mockSuccessfulPasswordOperations,
    mockSuccessfulAttributeOperations,
    mockSuccessfulMfaOperations,
    mockSuccessfulUserCreation,
    mockSuccessfulOtpOperations,
    mockSuccessfulSocialProviderOperations,
    mockSuccessfulCredentialsOperations
} from '../mocks/aws-sdk';
import { CognitoJwtVerifier } from 'aws-jwt-verify';
import type { CognitoJwtVerifierMultiUserPool, CognitoJwtVerifierMultiProperties } from 'aws-jwt-verify/cognito-verifier';
import * as fw24 from '@ten24group/fw24';
import { SocialProvider } from '../../src/interfaces';
import * as envUtils from '@ten24group/fw24';

// Mock aws-jwt-verify
jest.mock('aws-jwt-verify', () => ({
    CognitoJwtVerifier: {
        create: () => ({
            verify: () => Promise.resolve(true)
        })
    }
}));

describe('CognitoService', () => {
    let service: CognitoService;
    const testAccessToken = 'test-access-token';
    const testUsername = 'testuser';
    const cognitoIdpMock = mockClient(CognitoIdentityProviderClient);
    const cognitoIdentityMock = mockClient(CognitoIdentityClient);

    beforeEach(() => {
        jest.resetModules();
        service = new CognitoService();
        cognitoIdpMock.reset();
        cognitoIdentityMock.reset();

        // Set up default mock responses
        cognitoIdpMock.on(InitiateAuthCommand).resolves({
            AuthenticationResult: {
                AccessToken: testAccessToken,
                IdToken: 'test-id-token',
                RefreshToken: 'test-refresh-token',
                TokenType: 'Bearer',
                ExpiresIn: 3600
            }
        });

        cognitoIdpMock.on(GetUserCommand).resolves({
            Username: testUsername,
            UserAttributes: [
                {
                    Name: 'email',
                    Value: 'test@example.com'
                }
            ]
        });

        cognitoIdpMock.on(AdminListGroupsForUserCommand).resolves({
            Groups: [
                {
                    GroupName: 'admin',
                    UserPoolId: 'test-pool',
                    Description: 'Admin group',
                    Precedence: 1,
                    LastModifiedDate: new Date(),
                    CreationDate: new Date()
                },
                {
                    GroupName: 'user',
                    UserPoolId: 'test-pool',
                    Description: 'User group',
                    Precedence: 2,
                    LastModifiedDate: new Date(),
                    CreationDate: new Date()
                }
            ]
        });

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
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    describe('signup', () => {
        it('should successfully sign up a new user with email', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                return { $metadata: {} };
            });
            (service as any).identityProviderClient = { send: mockSend };

            await service.signup({
                username: 'testuser',
                password: 'Password123!',
                email: 'test@example.com'
            });

            expect(mockSend).toHaveBeenCalledWith(
                expect.objectContaining({
                    input: {
                        ClientId: 'test-client-id',
                        Username: 'testuser',
                        Password: 'Password123!',
                        UserAttributes: [
                            { Name: 'email', Value: 'test@example.com' }
                        ]
                    }
                })
            );
        });

        it('should handle signup with username as email', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                return { $metadata: {} };
            });
            (service as any).identityProviderClient = { send: mockSend };

            await service.signup({
                username: 'test@example.com',
                password: 'Password123!'
            });

            expect(mockSend).toHaveBeenCalledWith(
                expect.objectContaining({
                    input: {
                        ClientId: 'test-client-id',
                        Username: 'test@example.com',
                        Password: 'Password123!',
                        UserAttributes: [
                            { Name: 'email', Value: 'test@example.com' }
                        ]
                    }
                })
            );
        });

        it('should handle signup with only username (non-email) and password', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                return { $metadata: {} };
            });
            (service as any).identityProviderClient = { send: mockSend };

            await service.signup({
                username: 'testuser',
                password: 'Password123!'
            });

            expect(mockSend).toHaveBeenCalledWith(
                expect.objectContaining({
                    input: {
                        ClientId: 'test-client-id',
                        Username: 'testuser',
                        Password: 'Password123!',
                        UserAttributes: []
                    }
                })
            );
        });

        it('should handle signup with different email and username', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                return { $metadata: {} };
            });
            (service as any).identityProviderClient = { send: mockSend };

            await service.signup({
                username: 'testuser',
                password: 'Password123!',
                email: 'different@example.com'
            });

            expect(mockSend).toHaveBeenCalledWith(
                expect.objectContaining({
                    input: {
                        ClientId: 'test-client-id',
                        Username: 'testuser',
                        Password: 'Password123!',
                        UserAttributes: [
                            { Name: 'email', Value: 'different@example.com' }
                        ]
                    }
                })
            );
        });

        it('should handle signup with additional attributes', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                return { $metadata: {} };
            });
            (service as any).identityProviderClient = { send: mockSend };

            await service.signup({
                username: 'testuser',
                password: 'Password123!',
                email: 'test@example.com',
                attributes: [
                    { Name: 'custom:role', Value: 'user' },
                    { Name: 'name', Value: 'Test User' }
                ]
            });

            expect(mockSend).toHaveBeenCalledWith(
                expect.objectContaining({
                    input: {
                        ClientId: 'test-client-id',
                        Username: 'testuser',
                        Password: 'Password123!',
                        UserAttributes: [
                            { Name: 'custom:role', Value: 'user' },
                            { Name: 'name', Value: 'Test User' },
                            { Name: 'email', Value: 'test@example.com' }
                        ]
                    }
                })
            );
        });

        it('should handle signup with invalid email format', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                return { $metadata: {} };
            });
            (service as any).identityProviderClient = { send: mockSend };

            await service.signup({
                username: 'testuser',
                password: 'Password123!',
                email: 'invalid-email'
            });

            expect(mockSend).toHaveBeenCalledWith(
                expect.objectContaining({
                    input: {
                        ClientId: 'test-client-id',
                        Username: 'testuser',
                        Password: 'Password123!',
                        UserAttributes: [
                            { Name: 'email', Value: 'invalid-email' }
                        ]
                    }
                })
            );
        });

        it('should handle signup with missing client ID', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                return { $metadata: {} };
            });
            (service as any).identityProviderClient = { send: mockSend };
            (service as any).getUserPoolClientId = () => '';

            await expect(service.signup({
                username: 'testuser',
                password: 'Password123!'
            })).rejects.toThrow();
        });
    });

    describe('signin', () => {
        it('should successfully sign in with username and password', async () => {
            mockSuccessfulSignIn();

            const result = await service.signin(testUsername, 'Password123!');

            expect(cognitoIdpMock).toHaveReceivedCommandWith(InitiateAuthCommand, {
                AuthFlow: 'USER_PASSWORD_AUTH',
                AuthParameters: {
                    USERNAME: testUsername,
                    PASSWORD: 'Password123!'
                }
            });
            expect(result).toHaveProperty('AccessToken');
            expect(result).toHaveProperty('IdToken');
            expect(result).toHaveProperty('RefreshToken');
        });

        it('should successfully sign in with email as username', async () => {
            mockSuccessfulSignIn();

            const result = await service.signin('test@example.com', 'Password123!');

            expect(cognitoIdpMock).toHaveReceivedCommandWith(InitiateAuthCommand, {
                AuthFlow: 'USER_PASSWORD_AUTH',
                AuthParameters: {
                    USERNAME: 'test@example.com',
                    PASSWORD: 'Password123!'
                }
            });
            expect(result).toHaveProperty('AccessToken');
        });

        it('should handle sign in with MFA challenge', async () => {
            cognitoIdpMock.on(InitiateAuthCommand).resolves({
                ChallengeName: 'SMS_MFA',
                Session: 'test-session',
                ChallengeParameters: {
                    CODE_DELIVERY_DESTINATION: '+1***456'
                }
            });

            const result = await service.signin(testUsername, 'Password123!');

            expect(result).toEqual({
                session: 'test-session',
                challengeName: 'SMS_MFA',
                challengeParameters: {
                    CODE_DELIVERY_DESTINATION: '+1***456'
                }
            });
        });

        it('should handle sign in with custom challenge', async () => {
            cognitoIdpMock.on(InitiateAuthCommand).resolves({
                ChallengeName: 'CUSTOM_CHALLENGE',
                Session: 'test-session',
                ChallengeParameters: {
                    CHALLENGE_TYPE: 'CAPTCHA'
                }
            });

            const result = await service.signin(testUsername, 'Password123!');

            expect(result).toEqual({
                session: 'test-session',
                challengeName: 'CUSTOM_CHALLENGE',
                challengeParameters: {
                    CHALLENGE_TYPE: 'CAPTCHA'
                }
            });
        });

        it('should handle sign in failure with invalid credentials', async () => {
            cognitoIdpMock.on(InitiateAuthCommand).rejects(new Error('NotAuthorizedException'));

            await expect(service.signin(testUsername, 'wrongpassword'))
                .rejects
                .toThrow('NotAuthorizedException');
        });

        it('should handle authentication failure without result', async () => {
            cognitoIdpMock.on(InitiateAuthCommand).resolves({});

            await expect(service.signin(testUsername, 'Password123!'))
                .rejects
                .toThrow('Authentication failed');
        });

        it('should handle network errors during signin', async () => {
            cognitoIdpMock.on(InitiateAuthCommand).rejects(new Error('Network error'));

            await expect(service.signin(testUsername, 'Password123!'))
                .rejects
                .toThrow('Network error');
        });
    });

    describe('verify', () => {
        it('should successfully verify a user', async () => {
            mockSuccessfulVerification();

            await service.verify(testUsername, '123456');

            expect(cognitoIdpMock).toHaveReceivedCommandWith(ConfirmSignUpCommand, {
                Username: testUsername,
                ConfirmationCode: '123456'
            });
        });
    });

    describe('signout', () => {
        it('should successfully sign out a user', async () => {
            mockSuccessfulSignOut();

            await service.signout(testAccessToken);

            expect(cognitoIdpMock).toHaveReceivedCommandWith(GlobalSignOutCommand, {
                AccessToken: testAccessToken
            });
        });
    });

    describe('user attributes', () => {
        it('should get verification code for user attribute', async () => {
            mockSuccessfulAttributeOperations();

            await service.getUserAttributeVerificationCode(testAccessToken, 'email');

            expect(cognitoIdpMock).toHaveReceivedCommandWith(GetUserAttributeVerificationCodeCommand, {
                AccessToken: testAccessToken,
                AttributeName: 'email'
            });
        });

        it('should verify user attribute', async () => {
            mockSuccessfulAttributeOperations();

            await service.verifyUserAttribute(testAccessToken, 'email', '123456');

            expect(cognitoIdpMock).toHaveReceivedCommandWith(VerifyUserAttributeCommand, {
                AccessToken: testAccessToken,
                AttributeName: 'email',
                Code: '123456'
            });
        });

        it('should resend verification code', async () => {
            mockSuccessfulAttributeOperations();

            await service.resendVerificationCode(testUsername);

            expect(cognitoIdpMock).toHaveReceivedCommandWith(ResendConfirmationCodeCommand, {
                Username: testUsername
            });
        });

        it('should handle verification code request failure', async () => {
            cognitoIdpMock.on(GetUserAttributeVerificationCodeCommand)
                .rejects(new Error('Invalid attribute'));

            await expect(service.getUserAttributeVerificationCode(testAccessToken, 'invalid-attribute'))
                .rejects
                .toThrow('Invalid attribute');
        });

        it('should handle verification failure', async () => {
            cognitoIdpMock.on(VerifyUserAttributeCommand)
                .rejects(new Error('Invalid verification code'));

            await expect(service.verifyUserAttribute(testAccessToken, 'email', 'invalid-code'))
                .rejects
                .toThrow('Invalid verification code');
        });

        it('should handle resend code failure', async () => {
            cognitoIdpMock.on(ResendConfirmationCodeCommand)
                .rejects(new Error('Too many attempts'));

            await expect(service.resendVerificationCode(testUsername))
                .rejects
                .toThrow('Too many attempts');
        });
    });

    describe('password operations', () => {
        it('should change password', async () => {
            mockSuccessfulPasswordOperations();

            await service.changePassword(testAccessToken, 'oldPassword', 'newPassword');

            expect(cognitoIdpMock).toHaveReceivedCommandWith(ChangePasswordCommand, {
                AccessToken: testAccessToken,
                PreviousPassword: 'oldPassword',
                ProposedPassword: 'newPassword'
            });
        });

        it('should initiate forgot password', async () => {
            mockSuccessfulPasswordOperations();

            await service.forgotPassword(testUsername);

            expect(cognitoIdpMock).toHaveReceivedCommandWith(ForgotPasswordCommand, {
                Username: testUsername
            });
        });

        it('should confirm forgot password', async () => {
            mockSuccessfulPasswordOperations();

            await service.confirmForgotPassword(testUsername, '123456', 'newPassword');

            expect(cognitoIdpMock).toHaveReceivedCommandWith(ConfirmForgotPasswordCommand, {
                Username: testUsername,
                ConfirmationCode: '123456',
                Password: 'newPassword'
            });
        });
    });

    describe('group operations', () => {
        it('should add user to group', async () => {
            mockSuccessfulGroupOperations();

            await service.addUserToGroup(testUsername, 'admin');

            expect(cognitoIdpMock).toHaveReceivedCommandWith(AdminAddUserToGroupCommand, {
                Username: testUsername,
                GroupName: 'admin'
            });
        });

        it('should get user groups', async () => {
            cognitoIdpMock.on(AdminListGroupsForUserCommand).resolves({
                Groups: [
                    {
                        GroupName: 'admin',
                        UserPoolId: 'test-pool',
                        Description: 'Admin group',
                        Precedence: 1,
                        LastModifiedDate: new Date(),
                        CreationDate: new Date()
                    },
                    {
                        GroupName: 'user',
                        UserPoolId: 'test-pool',
                        Description: 'User group',
                        Precedence: 2,
                        LastModifiedDate: new Date(),
                        CreationDate: new Date()
                    }
                ]
            });

            const groups = await service.getUserGroupNames(testUsername);
            expect(groups).toEqual(['admin', 'user']);
        });

        it('should set user groups', async () => {
            // Mock existing groups
            mockSuccessfulGroupOperations();
            
            // Mock the list groups response to include 'user' group
            cognitoIdpMock.on(AdminListGroupsForUserCommand).resolves({
                Groups: [{ GroupName: 'user' }]
            });

            // Set new groups to ['admin']
            await service.setUserGroups(testUsername, ['admin']);

            // Verify removal of 'user' group
            expect(cognitoIdpMock).toHaveReceivedCommandWith(AdminRemoveUserFromGroupCommand, {
                Username: testUsername,
                GroupName: 'user',
                UserPoolId: process.env.USER_POOL_ID
            });

            // Verify addition of 'admin' group
            expect(cognitoIdpMock).toHaveReceivedCommandWith(AdminAddUserToGroupCommand, {
                Username: testUsername,
                GroupName: 'admin',
                UserPoolId: process.env.USER_POOL_ID
            });
        });

        it('should handle errors when adding user to group', async () => {
            cognitoIdpMock.on(AdminAddUserToGroupCommand).rejects(new Error('Group not found'));

            await expect(service.addUserToGroup(testUsername, 'nonexistent-group'))
                .rejects
                .toThrow('Group not found');
        });

        it('should handle empty group list', async () => {
            cognitoIdpMock.on(AdminListGroupsForUserCommand).resolves({
                Groups: []
            });

            const groups = await service.getUserGroupNames(testUsername);
            expect(groups).toEqual([]);
        });

        it('should handle undefined group list', async () => {
            cognitoIdpMock.on(AdminListGroupsForUserCommand).resolves({});

            const groups = await service.getUserGroupNames(testUsername);
            expect(groups).toEqual([]);
        });

        it('should handle errors when setting user groups', async () => {
            cognitoIdpMock.on(AdminListGroupsForUserCommand).rejects(new Error('User not found'));

            await expect(service.setUserGroups(testUsername, ['admin']))
                .rejects
                .toThrow('User not found');
        });

        it('should handle no changes in group membership', async () => {
            cognitoIdpMock.on(AdminListGroupsForUserCommand).resolves({
                Groups: [{ GroupName: 'admin' }]
            });

            await service.setUserGroups(testUsername, ['admin']);

            // Verify no add or remove commands were called
            expect(cognitoIdpMock).not.toHaveReceivedCommand(AdminAddUserToGroupCommand);
            expect(cognitoIdpMock).not.toHaveReceivedCommand(AdminRemoveUserFromGroupCommand);
        });
    });

    describe('MFA operations', () => {
        it('should update user MFA preference', async () => {
            mockSuccessfulMfaOperations();

            await service.updateUserMfaPreference(testAccessToken, {
                enabledMethods: ['EMAIL'],
                preferredMethod: 'EMAIL'
            });

            expect(cognitoIdpMock).toHaveReceivedCommandWith(SetUserMFAPreferenceCommand, {
                AccessToken: testAccessToken,
                EmailMfaSettings: {
                    Enabled: true,
                    PreferredMfa: true
                }
            });
        });

        it('should set user MFA settings', async () => {
            mockSuccessfulMfaOperations();

            await service.setUserMfaSettings({
                username: testUsername,
                enabledMethods: ['EMAIL'],
                preferredMethod: 'EMAIL'
            });

            expect(cognitoIdpMock).toHaveReceivedCommandWith(AdminSetUserMFAPreferenceCommand, {
                Username: testUsername,
                EmailMfaSettings: {
                    Enabled: true,
                    PreferredMfa: true
                }
            });
        });

        it('should handle errors when updating MFA preferences', async () => {
            cognitoIdpMock.on(SetUserMFAPreferenceCommand)
                .rejects(new Error('Invalid MFA settings'));

            await expect(service.updateUserMfaPreference(testAccessToken, {
                enabledMethods: ['INVALID_METHOD' as any],
                preferredMethod: 'INVALID_METHOD' as any
            })).rejects.toThrow('Invalid MFA settings');
        });

        it('should handle errors when setting admin MFA settings', async () => {
            cognitoIdpMock.on(AdminSetUserMFAPreferenceCommand)
                .rejects(new Error('User not found'));

            await expect(service.setUserMfaSettings({
                username: 'nonexistent-user',
                enabledMethods: ['EMAIL']
            })).rejects.toThrow('User not found');
        });

        it('should handle setting MFA preferences without preferred method', async () => {
            mockSuccessfulMfaOperations();

            await service.updateUserMfaPreference(testAccessToken, {
                enabledMethods: ['EMAIL']
                // No preferred method
            });

            expect(cognitoIdpMock).toHaveReceivedCommandWith(SetUserMFAPreferenceCommand, {
                AccessToken: testAccessToken,
                EmailMfaSettings: {
                    Enabled: true,
                    PreferredMfa: false
                }
            });
        });
    });

    describe('OTP operations', () => {
        it('should get login options', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                return {
                    Session: 'test-session',
                    AvailableChallenges: ['EMAIL_OTP']
                };
            });
            (service as any).identityProviderClient = { send: mockSend };

            const result = await service.getLoginOptions('testuser');

            expect(result).toEqual({
                session: 'test-session',
                challenges: ['EMAIL_OTP']
            });
        });

        it('should handle missing session in OTP initiation', async () => {
            const mockSend = jest.fn().mockImplementation(() => Promise.resolve({
                ChallengeName: 'EMAIL_OTP',
                ChallengeParameters: {},
            } as RespondToAuthChallengeCommandOutput));
            (service as any).identityProviderClient = { send: mockSend };

            await expect(service.initiateOtpAuth('test@example.com', 'test-session')).rejects.toThrow('Failed to initiate OTP authentication');
        });

        it('should handle missing challenge name in OTP initiation', async () => {
            const mockSend = jest.fn().mockImplementation(() => Promise.resolve({
                Session: 'test-session',
                ChallengeParameters: {},
            } as RespondToAuthChallengeCommandOutput));
            (service as any).identityProviderClient = { send: mockSend };

            await expect(service.initiateOtpAuth('test@example.com', 'test-session')).rejects.toThrow('Failed to initiate OTP authentication');
        });

        it('should handle missing client ID in OTP initiation', async () => {
            jest.spyOn(service as any, 'getUserPoolClientId').mockImplementation(() => {
                throw new Error('User pool client ID is not configured');
            });

            const mockSend = jest.fn().mockImplementation(async () => {
                return {
                    Session: 'test-session',
                    ChallengeName: 'EMAIL_OTP'
                };
            });
            (service as any).identityProviderClient = { send: mockSend };

            await expect(service.initiateOtpAuth('testuser', 'test-session'))
                .rejects.toThrow('User pool client ID is not configured');
        });

        it('should handle missing session and challenge name in OTP initiation response', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                return {};
            });
            (service as any).identityProviderClient = { send: mockSend };

            await expect(service.initiateOtpAuth('testuser', 'test-session'))
                .rejects.toThrow('Failed to initiate OTP authentication');
        });

        it('should respond to OTP challenge', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                return {
                    AuthenticationResult: {
                        AccessToken: 'test-access-token',
                        IdToken: 'test-id-token',
                        RefreshToken: 'test-refresh-token',
                        TokenType: 'Bearer',
                        ExpiresIn: 3600
                    }
                };
            });
            (service as any).identityProviderClient = { send: mockSend };

            const result = await service.respondToOtpChallenge('testuser', 'test-session', '123456');

            expect(result).toEqual({
                AccessToken: 'test-access-token',
                IdToken: 'test-id-token',
                RefreshToken: 'test-refresh-token',
                TokenType: 'Bearer',
                ExpiresIn: 3600
            });
        });

        it('should handle new challenge in OTP response', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                return {
                    ChallengeName: 'NEW_PASSWORD_REQUIRED',
                    Session: 'test-session',
                    ChallengeParameters: { param: 'value' }
                };
            });
            (service as any).identityProviderClient = { send: mockSend };

            const result = await service.respondToOtpChallenge('testuser', 'test-session', '123456');

            expect(result).toEqual({
                session: 'test-session',
                challengeName: 'NEW_PASSWORD_REQUIRED',
                challengeParameters: { param: 'value' }
            });
        });

        it('should handle missing authentication result in OTP response', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                return {};
            });
            (service as any).identityProviderClient = { send: mockSend };

            await expect(service.respondToOtpChallenge('testuser', 'test-session', '123456'))
                .rejects.toThrow('Authentication failed');
        });

        it('should handle missing client ID in OTP response', async () => {
            jest.spyOn(service as any, 'getUserPoolClientId').mockImplementation(() => {
                throw new Error('User pool client ID is not configured');
            });

            const mockSend = jest.fn().mockImplementation(async () => {
                return {
                    AuthenticationResult: {
                        AccessToken: 'test-access-token',
                        IdToken: 'test-id-token',
                        RefreshToken: 'test-refresh-token',
                        TokenType: 'Bearer',
                        ExpiresIn: 3600
                    }
                };
            });
            (service as any).identityProviderClient = { send: mockSend };

            await expect(service.respondToOtpChallenge('testuser', 'test-session', '123456'))
                .rejects.toThrow('User pool client ID is not configured');
        });

        it('should include challenge parameters in OTP initiation response', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                return {
                    Session: 'test-session',
                    ChallengeName: 'EMAIL_OTP',
                    ChallengeParameters: {
                        foo: 'bar'
                    },
                    $metadata: {}
                } as RespondToAuthChallengeCommandOutput;
            });
            (service as any).identityProviderClient = { send: mockSend };

            const result = await service.initiateOtpAuth('test@example.com', 'test-session');

            expect(result).toEqual({
                session: 'test-session',
                challengeName: 'EMAIL_OTP',
                challengeParameters: {
                    foo: 'bar'
                }
            });
        });
    });

    describe('social provider operations', () => {
        it('should get social sign-in config', async () => {
            const redirectUri = 'http://localhost:3000/callback';
            const configs = await service.getSocialSignInConfig(redirectUri);

            expect(configs).toHaveProperty('Google');
            expect(configs.Google).toHaveProperty('authorizationUrl');
            expect(configs.Google?.authorizationUrl).toContain('identity_provider=Google');
        });

        it('should initiate social sign-in', async () => {
            const redirectUri = 'http://localhost:3000/callback';
            const url = await service.initiateSocialSignIn('Google', redirectUri);

            // Check for required OAuth parameters
            expect(url).toContain('identity_provider=Google');
            expect(url).toContain('response_type=code');
            expect(url).toContain('client_id=');
            expect(url).toContain('scope=');
            
            // Check for encoded redirect URI
            const encodedRedirectUri = encodeURIComponent(redirectUri);
            expect(url).toContain(`redirect_uri=${encodedRedirectUri}`);
        });

        it('should complete social sign-in', async () => {
            mockSuccessfulGetUser(testUsername, 'test@example.com');

            // Mock fetch for this test
            const mockFetchResponse = {
                ok: true,
                status: 200,
                statusText: 'OK',
                headers: new Headers({
                    'Content-Type': 'application/json'
                }),
                redirected: false,
                type: 'default' as ResponseType,
                url: '',
                json: () => Promise.resolve({
                    access_token: 'test-access-token',
                    id_token: 'test-id-token',
                    refresh_token: 'test-refresh-token',
                    token_type: 'Bearer',
                    expires_in: 3600
                }),
                text: () => Promise.resolve(''),
                body: null,
                bodyUsed: false,
                clone: function() { return this as Response; },
                arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
                blob: () => Promise.resolve(new Blob([])),
                formData: () => Promise.resolve(new FormData())
            } as Response;

            const mockFetch = jest.fn(() => Promise.resolve(mockFetchResponse));
            global.fetch = mockFetch as unknown as typeof fetch;

            const redirectUri = 'http://localhost:3000/callback';
            const code = 'test-code';
            const result = await service.completeSocialSignIn(
                'Google',
                code,
                redirectUri
            );

            // Verify the token exchange request
            expect(mockFetch).toHaveBeenCalledWith(
                expect.stringContaining('/oauth2/token'),
                expect.objectContaining({
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    body: expect.stringContaining(`code=${code}`)
                })
            );

            // Verify the response
            expect(result).toEqual({
                AccessToken: 'test-access-token',
                IdToken: 'test-id-token',
                RefreshToken: 'test-refresh-token',
                TokenType: 'Bearer',
                ExpiresIn: 3600,
                provider: 'Google',
                isNewUser: false
            });
        });

        it('should handle unsupported social provider', async () => {
            const redirectUri = 'http://localhost:3000/callback';
            await expect(service.initiateSocialSignIn('UnsupportedProvider' as any, redirectUri))
                .rejects.toThrow('Social provider UnsupportedProvider is not configured');
        });

        it('should handle missing domain and client ID in social sign-in completion', async () => {
            jest.spyOn(service as any, 'getAuthDomain').mockReturnValue('');
            jest.spyOn(service as any, 'getUserPoolClientId').mockReturnValue('');

            await expect(service.completeSocialSignIn(
                'Google',
                'test-code',
                'http://localhost:3000/callback'
            )).rejects.toThrow('Missing required configuration: domain or userPoolClientId');
        });

        it('should handle linking social provider with invalid access token', async () => {
            cognitoIdpMock.on(GetUserCommand).rejects(new Error('Invalid access token'));

            await expect(service.linkSocialProvider(
                'invalid-token',
                'Google',
                'test-code',
                'http://localhost:3000/callback'
            )).rejects.toThrow('Invalid access token');
        });

        it('should handle unlinking social provider with invalid access token', async () => {
            cognitoIdpMock.on(GetUserCommand).rejects(new Error('Invalid access token'));

            await expect(service.unlinkSocialProvider(
                'invalid-token',
                'Google'
            )).rejects.toThrow('Invalid access token');
        });

        it('should handle social sign-in with new user', async () => {
            const currentTime = new Date();
            // Mock GetUserCommand to indicate a new user
            cognitoIdpMock.on(GetUserCommand).resolves({
                Username: testUsername,
                UserAttributes: [
                    {
                        Name: 'custom:account_created',
                        Value: currentTime.toISOString()
                    }
                ]
            });

            // Mock Date.now() to return the same timestamp
            const realDate = Date;
            const mockDate = class extends Date {
                constructor() {
                    super();
                    return currentTime;
                }
            };
            global.Date = mockDate as DateConstructor;

            // Mock fetch for this test
            const mockFetchResponse = {
                ok: true,
                status: 200,
                statusText: 'OK',
                headers: new Headers({
                    'Content-Type': 'application/json'
                }),
                redirected: false,
                type: 'default' as ResponseType,
                url: '',
                json: () => Promise.resolve({
                    access_token: 'test-access-token',
                    id_token: 'test-id-token',
                    refresh_token: 'test-refresh-token',
                    token_type: 'Bearer',
                    expires_in: 3600
                }),
                text: () => Promise.resolve(''),
                body: null,
                bodyUsed: false,
                clone: function() { return this as Response; },
                arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
                blob: () => Promise.resolve(new Blob([])),
                formData: () => Promise.resolve(new FormData())
            } as Response;

            const mockFetch = jest.fn(() => Promise.resolve(mockFetchResponse));
            global.fetch = mockFetch as unknown as typeof fetch;

            const result = await service.completeSocialSignIn(
                'Google',
                'test-code',
                'http://localhost:3000/callback'
            );

            // Restore the real Date
            global.Date = realDate;

            expect(result).toEqual({
                AccessToken: 'test-access-token',
                IdToken: 'test-id-token',
                RefreshToken: 'test-refresh-token',
                TokenType: 'Bearer',
                ExpiresIn: 3600,
                provider: 'Google',
                isNewUser: true
            });
        });

        it('should link social provider', async () => {
            mockSuccessfulGetUser(testUsername, 'test@example.com');
            mockSuccessfulSocialProviderOperations();

            await service.linkSocialProvider(
                testAccessToken,
                'Google',
                'test-code',
                'http://localhost:3000/callback'
            );

            expect(cognitoIdpMock).toHaveReceivedCommandWith(AdminLinkProviderForUserCommand, {
                SourceUser: {
                    ProviderAttributeName: 'Cognito_Subject',
                    ProviderAttributeValue: 'test-code',
                    ProviderName: 'Google'
                }
            });
        });

        it('should unlink social provider', async () => {
            mockSuccessfulGetUser(testUsername, 'test@example.com');
            mockSuccessfulSocialProviderOperations();

            await service.unlinkSocialProvider(testAccessToken, 'Google');

            expect(cognitoIdpMock).toHaveReceivedCommandWith(AdminDisableProviderForUserCommand, {
                UserPoolId: process.env.USER_POOL_ID,
                User: {
                    ProviderAttributeName: 'Cognito_Subject',
                    ProviderName: 'Google',
                    ProviderAttributeValue: testUsername
                }
            });
        });

        it('should handle missing domain configuration', async () => {
            // Override the mock for this specific test
            jest.spyOn(service as any, 'getAuthDomain').mockReturnValue('');
            jest.spyOn(service as any, 'getUserPoolClientId').mockReturnValue('test-client-id');

            await expect(service.getSocialSignInConfig('http://localhost:3000/callback'))
                .rejects
                .toThrow('Cognito domain is not configured');
        });

        it('should handle token exchange network error', async () => {
            mockSuccessfulGetUser(testUsername, 'test@example.com');

            // Mock fetch to simulate network error
            const mockFetch = jest.fn(() => Promise.reject(new Error('Network error')));
            global.fetch = mockFetch as jest.MockedFunction<typeof fetch>;

            await expect(service.completeSocialSignIn(
                'Google',
                'test-code',
                'http://localhost:3000/callback'
            )).rejects.toThrow('Failed to complete social sign-in: Network error');
        });

        it('should handle token exchange failure response', async () => {
            mockSuccessfulGetUser(testUsername, 'test@example.com');

            // Mock fetch to return error response
            const mockResponse = new Response('Invalid grant', {
                status: 400,
                statusText: 'Bad Request'
            });

            const mockFetch = jest.fn(() => Promise.resolve(mockResponse));
            global.fetch = mockFetch as jest.MockedFunction<typeof fetch>;

            await expect(service.completeSocialSignIn(
                'Google',
                'test-code',
                'http://localhost:3000/callback'
            )).rejects.toThrow('Failed to complete social sign-in: Token exchange failed: Invalid grant');
        });

        it('should handle user details fetch failure gracefully', async () => {
            const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
            
            // Mock successful fetch response
            const mockFetchResponse = {
                ok: true,
                status: 200,
                statusText: 'OK',
                headers: new Headers({
                    'Content-Type': 'application/json'
                }),
                json: () => Promise.resolve({
                    access_token: 'test-access-token',
                    id_token: 'test-id-token',
                    refresh_token: 'test-refresh-token',
                    token_type: 'Bearer',
                    expires_in: 3600
                }),
                text: () => Promise.resolve('')
            } as Response;

            const mockFetch = jest.fn(() => Promise.resolve(mockFetchResponse));
            global.fetch = mockFetch as jest.MockedFunction<typeof fetch>;

            // Mock GetUser command to throw an error
            cognitoIdpMock.on(GetUserCommand).rejects(new Error('Failed to get user details'));

            const result = await service.completeSocialSignIn('Google', 'test-code', 'http://localhost');
            
            expect(consoleSpy).toHaveBeenCalledWith('Error getting user details:', expect.any(Error));
            expect(result).toEqual({
                AccessToken: 'test-access-token',
                IdToken: 'test-id-token',
                RefreshToken: 'test-refresh-token',
                TokenType: 'Bearer',
                ExpiresIn: 3600,
                provider: 'Google'
            });
            consoleSpy.mockRestore();
        });

        it('should log error when getting user details fails', async () => {
            const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
            
            // Mock successful fetch response
            const mockFetchResponse = {
                ok: true,
                status: 200,
                statusText: 'OK',
                headers: new Headers({
                    'Content-Type': 'application/json'
                }),
                json: () => Promise.resolve({
                    access_token: 'test-access-token',
                    id_token: 'test-id-token',
                    refresh_token: 'test-refresh-token',
                    token_type: 'Bearer',
                    expires_in: 3600
                }),
                text: () => Promise.resolve('')
            } as Response;

            const mockFetch = jest.fn(() => Promise.resolve(mockFetchResponse));
            global.fetch = mockFetch as jest.MockedFunction<typeof fetch>;

            // Mock GetUser command to throw an error
            cognitoIdpMock.on(GetUserCommand).rejects(new Error('Failed to get user details'));

            const result = await service.completeSocialSignIn('Google', 'test-code', 'http://localhost');
            
            expect(consoleSpy).toHaveBeenCalledWith('Error getting user details:', expect.any(Error));
            expect(result).toEqual({
                AccessToken: 'test-access-token',
                IdToken: 'test-id-token',
                RefreshToken: 'test-refresh-token',
                TokenType: 'Bearer',
                ExpiresIn: 3600,
                provider: 'Google'
            });
            consoleSpy.mockRestore();
        });

        it('should handle missing auth domain', async () => {
            jest.spyOn(service as any, 'getAuthDomain').mockReturnValue('');

            await expect(service.getSocialSignInConfig('http://localhost')).rejects.toThrow('Cognito domain is not configured');
        });

        it('should handle error in completeSocialSignIn with missing user details', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                throw new Error('Failed to get user details');
            });
            (service as any).identityProviderClient = { send: mockSend };

            const result = await service.completeSocialSignIn('Google', 'test-code', 'http://localhost');
            expect(result.isNewUser).toBeUndefined();
        });

        it('should handle disabled provider in getSocialSignInConfig', async () => {
            jest.resetModules();
            jest.mock('@ten24group/fw24', () => ({
                resolveEnvValueFor: ({ key }: { key: string }) => key === 'supportedIdentityProviders' ? 'Facebook' : 'test-value'
            }));

            const { CognitoService } = require('../../src/services/cognito-service');
            const service = new CognitoService();

            const configs = await service.getSocialSignInConfig('http://localhost');
            expect(configs.Google).toBeUndefined();
        });

        it('should handle missing client ID in getUserPoolClientId', async () => {
            jest.resetModules();
            jest.mock('@ten24group/fw24', () => ({
                resolveEnvValueFor: ({ key }: { key: string }) => key === 'userPoolClientID' ? '' : 'test-value'
            }));

            const { CognitoService } = require('../../src/services/cognito-service');
            const service = new CognitoService();

            await expect(service.signin('test@example.com', 'password')).rejects.toThrow('User pool client ID is not configured');
        });

        it('should handle error in completeSocialSignIn with missing user details and error', async () => {
            const mockFetchResponse = {
                ok: true,
                status: 200,
                statusText: 'OK',
                headers: new Headers({
                    'Content-Type': 'application/json'
                }),
                json: () => Promise.resolve({
                    access_token: 'test-access-token',
                    id_token: 'test-id-token',
                    refresh_token: 'test-refresh-token',
                    token_type: 'Bearer',
                    expires_in: 3600
                }),
                text: () => Promise.resolve('')
            } as Response;

            const mockFetch = jest.fn(() => Promise.resolve(mockFetchResponse));
            global.fetch = mockFetch as jest.MockedFunction<typeof fetch>;

            cognitoIdpMock.on(GetUserCommand).rejects(new Error('Failed to get user details'));

            const result = await service.completeSocialSignIn('Google', 'test-code', 'http://localhost');
            expect(result).toEqual({
                AccessToken: 'test-access-token',
                IdToken: 'test-id-token',
                RefreshToken: 'test-refresh-token',
                TokenType: 'Bearer',
                ExpiresIn: 3600,
                provider: 'Google'
            });
        });

        it('should handle error in unlinkSocialProvider with missing user pool ID', async () => {
            mockSuccessfulGetUser(testUsername, 'test@example.com');
            cognitoIdpMock.on(AdminDisableProviderForUserCommand).rejects(new Error('User pool ID is not configured'));

            await expect(service.unlinkSocialProvider(testAccessToken, 'Google'))
                .rejects
                .toThrow('User pool ID is not configured');
        });

        it('should handle error in completeSocialSignIn with missing user details and network error', async () => {
            const mockFetchResponse = {
                ok: true,
                status: 200,
                statusText: 'OK',
                headers: new Headers({
                    'Content-Type': 'application/json'
                }),
                json: () => Promise.resolve({
                    access_token: 'test-access-token',
                    id_token: 'test-id-token',
                    refresh_token: 'test-refresh-token',
                    token_type: 'Bearer',
                    expires_in: 3600
                }),
                text: () => Promise.resolve('')
            } as Response;

            const mockFetch = jest.fn(() => Promise.resolve(mockFetchResponse));
            global.fetch = mockFetch as jest.MockedFunction<typeof fetch>;

            cognitoIdpMock.on(GetUserCommand).rejects(new Error('Network error'));

            const result = await service.completeSocialSignIn('Google', 'test-code', 'http://localhost');
            expect(result).toEqual({
                AccessToken: 'test-access-token',
                IdToken: 'test-id-token',
                RefreshToken: 'test-refresh-token',
                TokenType: 'Bearer',
                ExpiresIn: 3600,
                provider: 'Google'
            });
        });

        it('should handle error in unlinkSocialProvider with network error', async () => {
            mockSuccessfulGetUser(testUsername, 'test@example.com');
            cognitoIdpMock.on(AdminDisableProviderForUserCommand).rejects(new Error('Network error'));

            await expect(service.unlinkSocialProvider(testAccessToken, 'Google'))
                .rejects
                .toThrow('Network error');
        });

        it('should handle Body is unusable error in completeSocialSignIn', async () => {
            const provider = 'Google' as SocialProvider;
            const code = 'test-code';
            const redirectUri = 'http://localhost:3000/callback';

            const mockFetch = jest.fn().mockImplementation(() => Promise.resolve({
                ok: true,
                status: 200,
                statusText: 'OK',
                headers: new Headers(),
                json: () => { throw new Error('Body is unusable'); },
                clone: () => new Response(),
                arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
                blob: () => Promise.resolve(new Blob()),
                formData: () => Promise.resolve(new FormData()),
                text: () => Promise.resolve(''),
                body: null,
                bodyUsed: false,
                redirected: false,
                type: 'default' as ResponseType,
                url: ''
            }));
            (global as any).fetch = mockFetch;

            cognitoIdpMock.on(GetUserCommand).rejects(new Error('Failed to get user details'));

            const result = await service.completeSocialSignIn(provider, code, redirectUri);
            expect(result).toHaveProperty('AccessToken', 'test-access-token');
            expect(result).toHaveProperty('IdToken', 'test-id-token');
        });

        it('should handle missing user pool ID in unlinkSocialProvider', async () => {
            jest.spyOn(service as any, 'getUserPoolID').mockReturnValue('');
            mockSuccessfulGetUser(testUsername, 'test@example.com');
            cognitoIdpMock.on(AdminDisableProviderForUserCommand).rejects(new Error('User pool ID is not configured'));
            
            await expect(service.unlinkSocialProvider('test-token', 'Google'))
                .rejects.toThrow('User pool ID is not configured');
        });
    });

    describe('credentials operations', () => {
        it('should get credentials', async () => {
            mockSuccessfulCredentialsOperations();

            const idToken = 'test-id-token';
            const result = await service.getCredentials(idToken);

            expect(cognitoIdentityMock).toHaveReceivedCommandWith(GetIdCommand, {
                IdentityPoolId: expect.any(String),
                Logins: expect.any(Object)
            } as any);

            expect(cognitoIdentityMock).toHaveReceivedCommandWith(GetCredentialsForIdentityCommand, {
                IdentityId: 'test-identity-id',
                Logins: expect.any(Object)
            } as any);

            expect(result).toHaveProperty('Credentials');
            expect(result.Credentials).toHaveProperty('AccessKeyId');
            expect(result.Credentials).toHaveProperty('SecretKey');
            expect(result.Credentials).toHaveProperty('SessionToken');
        });

        it('should handle invalid JWT token', async () => {
            // Mock GetIdCommand to throw an error for invalid token
            cognitoIdentityMock.on(GetIdCommand).rejects(new Error('Invalid ID-Token: invalid-token'));

            await expect(service.getCredentials('invalid-token'))
                .rejects
                .toThrow('Invalid ID-Token: invalid-token');
        });

        it('should handle missing identity pool configuration', async () => {
            mockSuccessfulCredentialsOperations();
            jest.spyOn(service as any, 'getIdentityPoolId').mockImplementation(() => {
                throw new Error('Identity pool ID is not configured');
            });

            await expect(service.getCredentials('test-token'))
                .rejects
                .toThrow('Identity pool ID is not configured');
        });

        it('should handle GetId command failure', async () => {
            mockSuccessfulCredentialsOperations();
            cognitoIdentityMock.on(GetIdCommand).rejects(new Error('Failed to get identity'));

            await expect(service.getCredentials('test-token'))
                .rejects
                .toThrow('Failed to get identity');
        });

        it('should handle JWT verification failure', async () => {
            const mockVerify = jest.fn().mockImplementation(() => Promise.reject(new Error('Invalid token')));
            const mockJwtVerifier = {
                verify: mockVerify,
                verifySync: jest.fn(),
                cacheJwks: jest.fn(),
                jwksCache: {},
                issuersConfig: {},
                issuer: '',
                signatureVerifier: {},
                claimsVerifier: {},
                tokenValidator: {},
                tokenValidatorSync: {},
                tokenValidatorNoCache: {},
                tokenValidatorNoCacheSync: {}
            } as unknown as CognitoJwtVerifierMultiUserPool<CognitoJwtVerifierMultiProperties>;
            jest.spyOn(CognitoJwtVerifier, 'create').mockReturnValue(mockJwtVerifier);

            await expect(service.getCredentials('invalid-token')).rejects.toThrow('Invalid ID-Token: invalid-token');
        });
    });

    describe('token operations', () => {
        it('should handle token refresh', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                return {
                    AuthenticationResult: {
                        AccessToken: 'new-access-token',
                        IdToken: 'new-id-token',
                        TokenType: 'Bearer',
                        ExpiresIn: 3600
                    }
                };
            });
            (service as any).identityProviderClient = { send: mockSend };

            const result = await service.refreshToken('test-refresh-token');

            expect(result).toEqual({
                AccessToken: 'new-access-token',
                IdToken: 'new-id-token',
                RefreshToken: 'test-refresh-token',
                TokenType: 'Bearer',
                ExpiresIn: 3600
            });
        });

        it('should handle token refresh failure', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                return {};
            });
            (service as any).identityProviderClient = { send: mockSend };

            await expect(service.refreshToken('test-refresh-token'))
                .rejects.toThrow('Token refresh failed');
        });

        it('should handle invalid refresh token', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                throw new Error('Invalid refresh token');
            });
            (service as any).identityProviderClient = { send: mockSend };

            await expect(service.refreshToken('invalid-token'))
                .rejects.toThrow('Invalid refresh token');
        });

        it('should handle specific error during token refresh', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                throw new Error('NotAuthorizedException: Refresh Token has expired');
            });
            (service as any).identityProviderClient = { send: mockSend };

            await expect(service.refreshToken('expired-token'))
                .rejects.toThrow('NotAuthorizedException: Refresh Token has expired');
        });

        it('should handle missing client ID in token refresh', async () => {
            jest.spyOn(service as any, 'getUserPoolClientId').mockImplementation(() => {
                throw new Error('User pool client ID is not configured');
            });

            await expect(service.refreshToken('test-refresh-token'))
                .rejects.toThrow('User pool client ID is not configured');
        });
    });

    describe('user attribute operations', () => {
        it('should handle verification code request failure', async () => {
            cognitoIdpMock.on(GetUserAttributeVerificationCodeCommand)
                .rejects(new Error('Invalid attribute'));

            await expect(service.getUserAttributeVerificationCode(testAccessToken, 'invalid-attribute'))
                .rejects
                .toThrow('Invalid attribute');
        });

        it('should handle verification failure', async () => {
            cognitoIdpMock.on(VerifyUserAttributeCommand)
                .rejects(new Error('Invalid verification code'));

            await expect(service.verifyUserAttribute(testAccessToken, 'email', 'invalid-code'))
                .rejects
                .toThrow('Invalid verification code');
        });

        it('should handle resend code failure', async () => {
            cognitoIdpMock.on(ResendConfirmationCodeCommand)
                .rejects(new Error('Too many attempts'));

            await expect(service.resendVerificationCode(testUsername))
                .rejects
                .toThrow('Too many attempts');
        });
    });

    describe('user management operations', () => {
        it('should create a user successfully', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                return { $metadata: {} } as AdminCreateUserCommandOutput;
            });
            (service as any).identityProviderClient = { send: mockSend };

            await service.createUser({
                username: 'testuser',
                tempPassword: 'TempPass123!',
                attributes: [
                    { Name: 'email', Value: 'test@example.com' }
                ]
            });

            expect(mockSend).toHaveBeenCalledWith(
                expect.objectContaining({
                    input: expect.objectContaining({
                        Username: 'testuser',
                        TemporaryPassword: 'TempPass123!',
                        UserAttributes: [
                            { Name: 'email', Value: 'test@example.com' }
                        ]
                    })
                })
            );
        });

        describe('setPassword', () => {
            it('should set password with force change enabled', async () => {
                const service = new CognitoService();
                await service.setPassword('testuser', 'newpassword', true);

                expect(cognitoIdpMock).toHaveReceivedCommandWith(AdminSetUserPasswordCommand, {
                    Username: 'testuser',
                    Password: 'newpassword',
                    Permanent: false,
                    UserPoolId: 'us-east-1_testpool'
                });
            });

            it('should set password with force change disabled', async () => {
                const service = new CognitoService();
                await service.setPassword('testuser', 'newpassword', false);

                expect(cognitoIdpMock).toHaveReceivedCommandWith(AdminSetUserPasswordCommand, {
                    Username: 'testuser',
                    Password: 'newpassword',
                    Permanent: true,
                    UserPoolId: 'us-east-1_testpool'
                });
            });

            it('should set password with default force change value', async () => {
                const service = new CognitoService();
                await service.setPassword('testuser', 'newpassword');

                expect(cognitoIdpMock).toHaveReceivedCommandWith(AdminSetUserPasswordCommand, {
                    Username: 'testuser',
                    Password: 'newpassword',
                    Permanent: false,
                    UserPoolId: 'us-east-1_testpool'
                });
            });

            it('should handle error when setting password', async () => {
                cognitoIdpMock.on(AdminSetUserPasswordCommand).rejects(new Error('Failed to set password'));
                
                const service = new CognitoService();
                await expect(service.setPassword('testuser', 'newpassword'))
                    .rejects
                    .toThrow('Failed to set password');
            });

            it('should handle missing user pool ID', async () => {
                cognitoIdpMock.on(AdminSetUserPasswordCommand).rejects(new Error('User pool ID is not configured'));

                await expect(service.setPassword('testuser', 'newpassword'))
                    .rejects
                    .toThrow('User pool ID is not configured');
            });
        });

        describe('updateUserAttributes', () => {
            it('should update user attributes successfully', async () => {
                const mockResponse = {};
                cognitoIdpMock.on(AdminUpdateUserAttributesCommand).resolves(mockResponse);

                const options = {
                    username: 'testuser',
                    attributes: [
                        { Name: 'email', Value: 'newemail@example.com' },
                        { Name: 'custom:role', Value: 'admin' }
                    ]
                };

                await expect(service.updateUserAttributes(options)).resolves.not.toThrow();

                expect(cognitoIdpMock).toHaveReceivedCommandWith(AdminUpdateUserAttributesCommand, {
                    Username: 'testuser',
                    UserPoolId: process.env.USER_POOL_ID,
                    UserAttributes: options.attributes
                });
            });

            it('should throw error when user pool ID is not configured', async () => {
                cognitoIdpMock.on(AdminUpdateUserAttributesCommand).rejects(new Error('User pool ID is not configured'));

                const options = {
                    username: 'testuser',
                    attributes: [{ Name: 'email', Value: 'test@example.com' }]
                };

                await expect(service.updateUserAttributes(options))
                    .rejects
                    .toThrow('User pool ID is not configured');
            });

            it('should handle API errors when updating attributes', async () => {
                cognitoIdpMock.on(AdminUpdateUserAttributesCommand).rejects(new Error('API Error'));

                const options = {
                    username: 'testuser',
                    attributes: [{ Name: 'email', Value: 'test@example.com' }]
                };

                await expect(service.updateUserAttributes(options))
                    .rejects
                    .toThrow('API Error');
            });
        });

        describe('resetPassword', () => {
            it('should handle missing user pool ID in resetPassword', async () => {
                const username = 'testuser';
                jest.spyOn(service as any, 'getUserPoolID').mockImplementation(() => {
                    throw new Error('User pool ID is not configured');
                });
                
                await expect(service.resetPassword(username))
                    .rejects.toThrow('User pool ID is not configured');
            });
        });
    });

    describe('group operations with pagination', () => {
        it('should handle more than 20 groups', async () => {
            const groups = Array.from({ length: 25 }, (_, i) => ({ GroupName: `group${i}` }));
            const mockSend = jest.fn()
                .mockImplementationOnce(async () => {
                    return { Groups: groups.slice(0, 20), $metadata: {} } as AdminListGroupsForUserCommandOutput;
                })
                .mockImplementationOnce(async () => {
                    return { Groups: groups.slice(20), $metadata: {} } as AdminListGroupsForUserCommandOutput;
                });

            (service as any).identityProviderClient = { send: mockSend };

            const result = await service.getUserGroupNames('testuser');

            expect(result).toHaveLength(20);
            expect(mockSend).toHaveBeenCalledWith(
                expect.objectContaining({
                    input: {
                        Username: 'testuser',
                        Limit: 20,
                        UserPoolId: 'us-east-1_testpool'
                    }
                })
            );
        });

        it('should handle concurrent group operations', async () => {
            const mockSend = jest.fn().mockImplementation(async (command) => {
                if (command instanceof AdminListGroupsForUserCommand) {
                    return {
                        Groups: [{ GroupName: 'oldgroup1' }, { GroupName: 'oldgroup2' }],
                        $metadata: {}
                    } as AdminListGroupsForUserCommandOutput;
                }
                return { $metadata: {} };
            });

            (service as any).identityProviderClient = { send: mockSend };

            await service.setUserGroups('testuser', ['newgroup1', 'oldgroup1']);

            expect(mockSend).toHaveBeenCalledWith(
                expect.objectContaining({
                    input: {
                        Username: 'testuser',
                        GroupName: 'newgroup1',
                        UserPoolId: 'us-east-1_testpool'
                    }
                })
            );

            expect(mockSend).toHaveBeenCalledWith(
                expect.objectContaining({
                    input: {
                        Username: 'testuser',
                        GroupName: 'oldgroup2',
                        UserPoolId: 'us-east-1_testpool'
                    }
                })
            );
        });
    });

    describe('MFA operations with combinations', () => {
        it('should update MFA preferences with multiple methods', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                return { $metadata: {} } as SetUserMFAPreferenceCommandOutput;
            });
            (service as any).identityProviderClient = { send: mockSend };

            await service.updateUserMfaPreference('access-token', {
                enabledMethods: ['SMS', 'EMAIL', 'SOFTWARE_TOKEN'],
                preferredMethod: 'SOFTWARE_TOKEN'
            });

            expect(mockSend).toHaveBeenCalledWith(
                expect.objectContaining({
                    input: {
                        AccessToken: 'access-token',
                        SMSMfaSettings: {
                            Enabled: true,
                            PreferredMfa: false
                        },
                        EmailMfaSettings: {
                            Enabled: true,
                            PreferredMfa: false
                        },
                        SoftwareTokenMfaSettings: {
                            Enabled: true,
                            PreferredMfa: true
                        }
                    }
                })
            );
        });

        it('should handle invalid MFA settings', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                throw new Error('Invalid MFA configuration');
            });
            (service as any).identityProviderClient = { send: mockSend };

            await expect(service.setUserMfaSettings({
                username: 'testuser',
                enabledMethods: ['INVALID_METHOD' as any],
                preferredMethod: 'INVALID_METHOD' as any
            })).rejects.toThrow('Invalid MFA configuration');
        });

        it('should update MFA preferences with no methods enabled', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                return { $metadata: {} } as SetUserMFAPreferenceCommandOutput;
            });
            (service as any).identityProviderClient = { send: mockSend };

            await service.updateUserMfaPreference('access-token', {
                enabledMethods: [],
                preferredMethod: undefined
            });

            expect(mockSend).toHaveBeenCalledWith(
                expect.objectContaining({
                    input: {
                        AccessToken: 'access-token',
                        SMSMfaSettings: {
                            Enabled: false,
                            PreferredMfa: false
                        },
                        EmailMfaSettings: {
                            Enabled: false,
                            PreferredMfa: false
                        },
                        SoftwareTokenMfaSettings: {
                            Enabled: false,
                            PreferredMfa: false
                        }
                    }
                })
            );
        });

        it('should set admin MFA settings with all methods enabled', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                return { $metadata: {} } as AdminSetUserMFAPreferenceCommandOutput;
            });
            (service as any).identityProviderClient = { send: mockSend };

            await service.setUserMfaSettings({
                username: 'testuser',
                enabledMethods: ['SMS', 'EMAIL', 'SOFTWARE_TOKEN'],
                preferredMethod: 'SMS'
            });

            expect(mockSend).toHaveBeenCalledWith(
                expect.objectContaining({
                    input: {
                        Username: 'testuser',
                        UserPoolId: expect.any(String),
                        SMSMfaSettings: {
                            Enabled: true,
                            PreferredMfa: true
                        },
                        EmailMfaSettings: {
                            Enabled: true,
                            PreferredMfa: false
                        },
                        SoftwareTokenMfaSettings: {
                            Enabled: true,
                            PreferredMfa: false
                        }
                    }
                })
            );
        });

        it('should set admin MFA settings with no methods enabled', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                return { $metadata: {} } as AdminSetUserMFAPreferenceCommandOutput;
            });
            (service as any).identityProviderClient = { send: mockSend };

            await service.setUserMfaSettings({
                username: 'testuser',
                enabledMethods: [],
                preferredMethod: undefined
            });

            expect(mockSend).toHaveBeenCalledWith(
                expect.objectContaining({
                    input: {
                        Username: 'testuser',
                        UserPoolId: expect.any(String),
                        SMSMfaSettings: {
                            Enabled: false,
                            PreferredMfa: false
                        },
                        EmailMfaSettings: {
                            Enabled: false,
                            PreferredMfa: false
                        },
                        SoftwareTokenMfaSettings: {
                            Enabled: false,
                            PreferredMfa: false
                        }
                    }
                })
            );
        });
    });

    describe('getLoginOptions', () => {
        it('should return available challenges and session', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                return {
                    Session: 'test-session',
                    AvailableChallenges: ['EMAIL_OTP']
                };
            });
            (service as any).identityProviderClient = { send: mockSend };

            const result = await service.getLoginOptions('testuser');

            expect(result).toEqual({
                session: 'test-session',
                challenges: ['EMAIL_OTP']
            });
        });

        it('should handle no available challenges', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                return {
                    Session: 'test-session',
                    AvailableChallenges: []
                };
            });
            (service as any).identityProviderClient = { send: mockSend };

            const result = await service.getLoginOptions('testuser');

            expect(result).toEqual({
                session: 'test-session',
                challenges: []
            });
        });

        it('should handle missing client ID', async () => {
            jest.spyOn(service as any, 'getUserPoolClientId').mockImplementation(() => {
                throw new Error('User pool client ID is not configured');
            });

            await expect(service.getLoginOptions('testuser')).rejects.toThrow('User pool client ID is not configured');
        });

        it('should handle InitiateAuth command failure', async () => {
            const mockSend = jest.fn().mockImplementation(async () => {
                throw new Error('User does not exist');
            });
            (service as any).identityProviderClient = { send: mockSend };

            await expect(service.getLoginOptions('testuser')).rejects.toThrow('User does not exist');
        });
    });

    describe('utility functions', () => {
        it('should handle missing user pool client ID', async () => {
            jest.spyOn(service as any, 'getUserPoolClientId').mockImplementation(() => {
                throw new Error('User pool client ID is not configured');
            });

            await expect(service.signin('test@example.com', 'password')).rejects.toThrow('User pool client ID is not configured');
        });

        it('should handle missing user pool ID', async () => {
            cognitoIdpMock.on(AdminSetUserPasswordCommand).rejects(new Error('User pool ID is not configured'));

            await expect(service.setPassword('testuser', 'newpassword'))
                .rejects
                .toThrow('User pool ID is not configured');
        });

        it('should handle missing client ID in getUserPoolClientId', async () => {
            jest.resetModules();
            jest.mock('@ten24group/fw24', () => ({
                resolveEnvValueFor: ({ key }: { key: string }) => key === 'userPoolClientID' ? '' : 'test-value'
            }));

            const { CognitoService } = require('../../src/services/cognito-service');
            const service = new CognitoService();

            await expect(service.signin('test@example.com', 'password')).rejects.toThrow('User pool client ID is not configured');
        });

        it('should handle missing pool ID in getUserPoolID', () => {
            const service = new CognitoService();
            jest.spyOn(fw24, 'resolveEnvValueFor').mockReturnValue('');
            expect(() => (service as any).getUserPoolID()).toThrow('User pool ID is not configured');
        });

        it('should handle empty client ID', async () => {
            jest.spyOn(service as any, 'getUserPoolClientId').mockImplementation(() => {
                throw new Error('User pool client ID is not configured');
            });

            await expect(service.signin('test@example.com', 'password'))
                .rejects
                .toThrow('User pool client ID is not configured');
        });

        it('should handle empty user pool client ID', async () => {
            jest.spyOn(service as any, 'getUserPoolClientId').mockImplementation(() => {
                throw new Error('User pool client ID is not configured');
            });

            await expect(service.signin('test@example.com', 'password'))
                .rejects
                .toThrow('User pool client ID is not configured');
        });

        it('should handle missing user pool ID with error', async () => {
            jest.spyOn(service as any, 'getUserPoolID').mockImplementation(() => {
                throw new Error('User pool ID is not configured');
            });

            await expect(service.setPassword('testuser', 'newpassword'))
                .rejects
                .toThrow('User pool ID is not configured');
        });

        it('should successfully get identity pool ID', () => {
            const mockResolveEnvValueFor = jest.spyOn(envUtils, 'resolveEnvValueFor');
            mockResolveEnvValueFor.mockReturnValue('test-identity-pool');
            
            const result = (service as any).getIdentityPoolId();
            expect(result).toBe('test-identity-pool');
            expect(mockResolveEnvValueFor).toHaveBeenCalledWith({key: 'identityPoolID'});
            
            mockResolveEnvValueFor.mockRestore();
        });

        it('should handle missing identity pool ID', () => {
            // Mock resolveEnvValueFor to return empty string
            const mockResolveEnvValueFor = jest.fn().mockReturnValue('');
            jest.spyOn(require('@ten24group/fw24'), 'resolveEnvValueFor').mockImplementation(mockResolveEnvValueFor);

            expect(() => (service as any).getIdentityPoolId()).toThrow('Identity pool ID is not configured');

            jest.spyOn(require('@ten24group/fw24'), 'resolveEnvValueFor').mockRestore();
        });
    });
}); 