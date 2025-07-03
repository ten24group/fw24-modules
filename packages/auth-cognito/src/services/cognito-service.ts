import { CognitoIdentityProviderClient, SignUpCommand, InitiateAuthCommand, ConfirmSignUpCommand, GlobalSignOutCommand, ChangePasswordCommand, ForgotPasswordCommand, ConfirmForgotPasswordCommand, AdminAddUserToGroupCommand, AdminRemoveUserFromGroupCommand, AdminListGroupsForUserCommand, AdminSetUserPasswordCommand, AdminResetUserPasswordCommand, AdminCreateUserCommand, DeliveryMediumType, AdminUpdateUserAttributesCommand, ChallengeName, AuthenticationResultType, ChallengeNameType, RespondToAuthChallengeCommand, SetUserMFAPreferenceCommand, AdminSetUserMFAPreferenceCommand, ResendConfirmationCodeCommand, VerifyUserAttributeCommand, GetUserAttributeVerificationCodeCommand, InitiateAuthRequest, AssociateSoftwareTokenCommand, GetUserCommand, AdminLinkProviderForUserCommand, AdminDisableProviderForUserCommand, AdminGetUserCommand, ListUsersCommand, AdminDeleteUserCommand } from "@aws-sdk/client-cognito-identity-provider";
import { CognitoIdentityClient, GetIdCommand, GetCredentialsForIdentityCommand } from "@aws-sdk/client-cognito-identity";
import { CreateUserOptions, IAuthService, InitiateAuthResult, SignInResult, UpdateUserAttributeOptions, UserMfaPreferenceOptions, AdminMfaSettings, SignUpOptions, SocialProvider, SocialSignInResult, SocialSignInConfigs, UserDetails, DecodedIdToken, SignUpResult, SOCIAL_PROVIDERS, MfaMethod } from "../interfaces";
import { CognitoJwtVerifier } from "aws-jwt-verify";
import { createLogger, ILogger, resolveEnvValueFor } from "@ten24group/fw24";

export class CognitoService implements IAuthService {
    readonly logger: ILogger = createLogger(CognitoService);


    private identityProviderClient = new CognitoIdentityProviderClient({});
    private identityClient = new CognitoIdentityClient({});

    async signup(options: SignUpOptions): Promise<SignInResult | SignUpResult> {
        const { username, password, email, autoSignIn = false } = options;
        const userPoolClientId = this.getUserPoolClientId();

        if (!userPoolClientId) {
            throw new Error('User pool client ID is not configured');
        }

        // Build user attributes array with only standard Cognito attributes
        const userAttributes: Array<{ Name: string, Value: string }> = [];
        
        // Add standard Cognito attributes
        if (email) {
            userAttributes.push({
                Name: 'email',
                Value: email,
            });
        }
        // If no email provided but username looks like an email, use it as email
        else if (this.isValidEmail(username)) {
            userAttributes.push({
                Name: 'email',
                Value: username,
            });
        }

        // Convert all custom attributes to clientMetadata format
        const clientMetadata: { [key: string]: string } = {};
        Object.entries(options).forEach(([key, value]) => {
            // Skip reserved properties and standard Cognito attributes
            if (!['username', 'password', 'confirmPassword', 'email', 'autoSignIn'].includes(key)) {
                clientMetadata[key] = String(value);
            }
        });

        const result = await this.identityProviderClient.send(
            new SignUpCommand({
                ClientId: userPoolClientId,
                Username: username,
                Password: password,
                UserAttributes: userAttributes,
                ClientMetadata: clientMetadata
            })
        );

        // If autoSignIn is true, attempt to sign in immediately after signup
        if (autoSignIn) {
            return this.signin(username, password);
        }

        return {
            session: result.Session,
            UserConfirmed: result.UserConfirmed,
            UserSub: result.UserSub,
            CodeDeliveryDetails: result.CodeDeliveryDetails,
        }
    }

    // Helper method to validate email format
    private isValidEmail(email: string): boolean {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    async signin(username: string, password: string): Promise<SignInResult> {
        const userPoolClientId = this.getUserPoolClientId();

        const result = await this.identityProviderClient.send(
            new InitiateAuthCommand({
                AuthFlow: 'USER_PASSWORD_AUTH',
                ClientId: userPoolClientId,
                AuthParameters: {
                    USERNAME: username,
                    PASSWORD: password,
                },
            })
        );

        if (result.ChallengeName) {
            return {
                session: result.Session ?? '',
                challengeName: result.ChallengeName,
                challengeParameters: result.ChallengeParameters,
            }
        }

        if (!result.AuthenticationResult) {
            throw new Error('Authentication failed');
        }

        return result.AuthenticationResult!;
    }

    async respondToNewPasswordChallenge(username: string, newPassword: string, session: string): Promise<SignInResult> {
        const userPoolClientId = this.getUserPoolClientId();

        const result = await this.identityProviderClient.send(
            new RespondToAuthChallengeCommand({
                ClientId: userPoolClientId,
                ChallengeName: 'NEW_PASSWORD_REQUIRED',
                Session: session,
                ChallengeResponses: {
                    USERNAME: username,
                    NEW_PASSWORD: newPassword,
                }
            })
        );

        if (result.ChallengeName) {
            return {
                session: result.Session ?? '',
                challengeName: result.ChallengeName,
                challengeParameters: result.ChallengeParameters,
            };
        }

        if (!result.AuthenticationResult) {
            throw new Error('Failed to set new password');
        }

        return result.AuthenticationResult;
    }

    async signout(accessToken: string): Promise<void> {
        await this.identityProviderClient.send(
            new GlobalSignOutCommand({
                AccessToken: accessToken,
            })
        );
    }

    async verify(username: string, code: string): Promise<void> {
        const userPoolClientId = this.getUserPoolClientId();

        await this.identityProviderClient.send(
            new ConfirmSignUpCommand({
                ClientId: userPoolClientId,
                Username: username,
                ConfirmationCode: code,
            })
        );
    }

    async getUserAttributeVerificationCode(accessToken: string, attributeName: string): Promise<void> {
        await this.identityProviderClient.send(
            new GetUserAttributeVerificationCodeCommand({
                AccessToken: accessToken,
                AttributeName: attributeName,
            })
        );
    }

    async verifyUserAttribute(accessToken: string, attributeName: string, code: string): Promise<void> {
        await this.identityProviderClient.send(
            new VerifyUserAttributeCommand({
                AccessToken: accessToken,
                AttributeName: attributeName,
                Code: code,
            })
        );
    }

    async resendVerificationCode(username: string): Promise<any> {
        const userPoolClientId = this.getUserPoolClientId();

        const result = await this.identityProviderClient.send(
            new ResendConfirmationCodeCommand({
                ClientId: userPoolClientId,
                Username: username,
            })
        );

        return result;
    }

    async initiateAuth(username: string): Promise<InitiateAuthResult> {
        // This will throw if client ID is not configured
        const clientId = this.getUserPoolClientId();

        const result = await this.identityProviderClient.send(
            new InitiateAuthCommand({
                AuthFlow: 'USER_AUTH',
                ClientId: clientId,
                AuthParameters: {
                    USERNAME: username
                }
            })
        );

        return { challenges: result.AvailableChallenges ?? [], session: result.Session ?? '' };
    }

    async initiateOtpAuth(username: string, session: string): Promise<SignInResult> {
        // This will throw if client ID is not configured
        const clientId = this.getUserPoolClientId();

        const response = await this.identityProviderClient.send(
            new RespondToAuthChallengeCommand({
                ClientId: clientId,
                ChallengeName: 'SELECT_CHALLENGE',
                Session: session,
                ChallengeResponses: {
                    USERNAME: username,
                    ANSWER: 'EMAIL_OTP'
                }
            })
        );

        if (!response.Session || !response.ChallengeName) {
            throw new Error('Failed to initiate OTP authentication');
        }

        return {
            session: response.Session,
            challengeName: response.ChallengeName,
            challengeParameters: response.ChallengeParameters,
        }
    }

    async respondToOtpChallenge(username: string, session: string, code: string): Promise<SignInResult> {        
        // This will throw if client ID is not configured
        const clientId = this.getUserPoolClientId();

        const result = await this.identityProviderClient.send(
            new RespondToAuthChallengeCommand({
                ClientId: clientId,
                ChallengeName: 'EMAIL_OTP',
                Session: session,
                ChallengeResponses: {
                    USERNAME: username,
                    EMAIL_OTP_CODE: code
                }
            })
        );

        if (result.ChallengeName) {
            return {
                session: result.Session ?? '',
                challengeName: result.ChallengeName,
                challengeParameters: result.ChallengeParameters,
            };
        }

        if (!result.AuthenticationResult) {
            throw new Error('Authentication failed');
        }

        return result.AuthenticationResult;
    }

    async refreshToken(refreshToken: string): Promise<AuthenticationResultType> {
        // This will throw if client ID is not configured
        const clientId = this.getUserPoolClientId();

        try {
            const command = new InitiateAuthCommand({
                AuthFlow: 'REFRESH_TOKEN_AUTH',
                ClientId: clientId,
                AuthParameters: {
                    REFRESH_TOKEN: refreshToken
                }
            });

            const response = await this.identityProviderClient.send(command);
            if (!response.AuthenticationResult) {
                throw new Error('Token refresh failed');
            }

            return {
                ...response.AuthenticationResult,
                RefreshToken: refreshToken
            };
        } catch (error) {
            throw error;
        }
    }

    async changePassword(accessToken: string, newPassword: string, oldPassword?: string): Promise<void> {
        await this.identityProviderClient.send(
            new ChangePasswordCommand({
                AccessToken: accessToken,
                ProposedPassword: newPassword,
                PreviousPassword: oldPassword,
            })
        );
    }

    async createUser(options: CreateUserOptions): Promise<UserDetails> {
        const { username, tempPassword, attributes = [] } = options;

        const response = await this.identityProviderClient.send(
            new AdminCreateUserCommand({
                Username: username,
                UserPoolId: this.getUserPoolID(),
                TemporaryPassword: tempPassword,
                DesiredDeliveryMediums: [ DeliveryMediumType.EMAIL ],
                MessageAction: "SUPPRESS",
                UserAttributes: attributes,
            })
        );

        return response.User as UserDetails;
    }

    async setPassword(username: string, password: string, forceChangePassword = true) {
        await this.identityProviderClient.send(
            new AdminSetUserPasswordCommand({
                Username: username,
                Password: password,
                Permanent: !forceChangePassword,
                UserPoolId: this.getUserPoolID(),
            })
        );
    }

    async resetPassword(username: string) {
        await this.identityProviderClient.send(
            new AdminResetUserPasswordCommand({
                Username: username,
                UserPoolId: this.getUserPoolID(),
            })
        );
    }


    async forgotPassword(username: string) {
        const result = await this.identityProviderClient.send(
            new ForgotPasswordCommand({
                ClientId: this.getUserPoolClientId(),
                Username: username
            })
        );

        return result;
    }

    async confirmForgotPassword(username: string, code: string, newPassword: string): Promise<void> {
        await this.identityProviderClient.send(
            new ConfirmForgotPasswordCommand({
                ClientId: this.getUserPoolClientId(),
                Username: username,
                ConfirmationCode: code,
                Password: newPassword,
            })
        );
    }

    async addUserToGroup(username: string, groupName: string): Promise<void> {
        await this.identityProviderClient.send(
            new AdminAddUserToGroupCommand({
                UserPoolId: this.getUserPoolID(),
                GroupName: groupName,
                Username: username,
            })
        );
    }

    async removeUserFromGroup(username: string, groupName: string): Promise<void> {
        await this.identityProviderClient.send(
            new AdminRemoveUserFromGroupCommand({
                UserPoolId: this.getUserPoolID(),
                GroupName: groupName,
                Username: username,
            })
        );
    }

    async getUserGroupNames(username: string): Promise<Array<string>> {

        //! NOTE: if there are a lot of groups this function will only return first 20
        const groupsList = await this.identityProviderClient.send(
            new AdminListGroupsForUserCommand({
                UserPoolId: this.getUserPoolID(),
                Username: username,
                Limit: 20
            })
        );

        return groupsList.Groups?.map(g => g.GroupName ?? '') ?? [];
    }

    async setUserGroups(username: string, newGroups: string[], updateSocialProviders = true): Promise<void> {
        const socialProviderList = this.getSupportedSocialProviders();
        // if social provider is enabled, get all the users from this username
        if (updateSocialProviders) {
            // get the user email
            const user = await this.identityProviderClient.send(
                new AdminGetUserCommand({
                    UserPoolId: this.getUserPoolID(),
                    Username: username,
                })
            );
            // get all the users with the same email
            const users = await this.identityProviderClient.send(
                new ListUsersCommand({
                    UserPoolId: this.getUserPoolID(),
                    Filter: `email = "${user.UserAttributes?.find(attr => attr.Name === 'email')?.Value}"`,
                })
            );
            if (users.Users) {
                for (const user of users.Users) {
                    await this.setUserGroups(user.Username!, newGroups, false);
                }
            }
        }
        
        const existingUserGroups = await this.getUserGroupNames(username);
        const promises = [];

        // collect only the new groups to be added
        for (const group of newGroups) {
            if (!existingUserGroups.includes(group)) {
                promises.push(this.addUserToGroup(username, group))
            }
        }

        // collect any existing-groups which are not part of new-groups for removal
        for (const group of existingUserGroups) {
            // do not remove the social provider auto generated group
            const isSocialProviderGroup = socialProviderList.some(provider => group.endsWith(provider));
            if (
                !newGroups.includes(group) &&
                !isSocialProviderGroup
            ) {
                this.logger.debug('removing group', username, group, isSocialProviderGroup);
                promises.push(this.removeUserFromGroup(username, group))
            }
        }

        await Promise.all(promises);
    }

    async updateUserAttributes(options: UpdateUserAttributeOptions): Promise<void> {
        const { username, attributes } = options;

        await this.identityProviderClient.send(
            new AdminUpdateUserAttributesCommand({
                Username: username,
                UserPoolId: this.getUserPoolID(),
                UserAttributes: attributes,
            })
        );

    }

    async deleteUser(username: string): Promise<void> {
        await this.identityProviderClient.send(
            new AdminDeleteUserCommand({
                Username: username,
                UserPoolId: this.getUserPoolID(),
            })
        );
    }

    async updateUserMfaPreference(accessToken: string, mfaPreference: UserMfaPreferenceOptions): Promise<void> {
        const { enabledMethods, preferredMethod } = mfaPreference;
        
        await this.identityProviderClient.send(
            new SetUserMFAPreferenceCommand({
                AccessToken: accessToken,
                EmailMfaSettings: {
                    Enabled: enabledMethods.includes('EMAIL'),
                    PreferredMfa: preferredMethod === 'EMAIL',
                },
                SMSMfaSettings: {
                    Enabled: enabledMethods.includes('SMS'),
                    PreferredMfa: preferredMethod === 'SMS',
                },
                SoftwareTokenMfaSettings: {
                    Enabled: enabledMethods.includes('SOFTWARE_TOKEN'),
                    PreferredMfa: preferredMethod === 'SOFTWARE_TOKEN',
                },
            })
        );  
    }

    async getUserMfaPreference(accessToken: string): Promise<UserMfaPreferenceOptions> {
        try {
            const result = await this.identityProviderClient.send(
                new GetUserCommand({
                    AccessToken: accessToken,
                })
            );

            const enabledMethods: Array<MfaMethod> = [];
            let preferredMethod: MfaMethod | undefined = undefined;

            // Check MFA preferences from user attributes
            const mfaOptions = result.MFAOptions || [];
            
            for (const option of mfaOptions) {
                if (option.DeliveryMedium === 'EMAIL') {
                    enabledMethods.push('EMAIL');
                    if (!preferredMethod) preferredMethod = 'EMAIL';
                } else if (option.DeliveryMedium === 'SMS') {
                    enabledMethods.push('SMS');
                    if (!preferredMethod) preferredMethod = 'SMS';
                }
            }

            // Check for software token MFA (TOTP)
            // This requires checking if user has software token devices
            const userAttributes = result.UserAttributes || [];
            const hasSoftwareToken = userAttributes.some(attr => 
                attr.Name === 'software_token_mfa_settings' && attr.Value === 'enabled'
            );
            
            if (hasSoftwareToken) {
                enabledMethods.push('SOFTWARE_TOKEN');
                if (!preferredMethod) preferredMethod = 'SOFTWARE_TOKEN';
            }

            return {
                enabledMethods,
                preferredMethod: preferredMethod
            };
        } catch (error: any) {
            throw new Error(`Failed to get MFA preferences: ${error.message}`);
        }
    }

    async setUserMfaSettings(settings: AdminMfaSettings): Promise<void> {
        const { username, enabledMethods, preferredMethod } = settings;
        
        await this.identityProviderClient.send(
            new AdminSetUserMFAPreferenceCommand({
                Username: username,
                UserPoolId: this.getUserPoolID(),
                EmailMfaSettings: {
                    Enabled: enabledMethods.includes('EMAIL'),
                    PreferredMfa: preferredMethod === 'EMAIL',
                },
                SMSMfaSettings: {
                    Enabled: enabledMethods.includes('SMS'),
                    PreferredMfa: preferredMethod === 'SMS',
                },
                SoftwareTokenMfaSettings: {
                    Enabled: enabledMethods.includes('SOFTWARE_TOKEN'),
                    PreferredMfa: preferredMethod === 'SOFTWARE_TOKEN',
                },
            })
        );
    }

    async verifyIdToken(idToken: string): Promise<DecodedIdToken> {
        const jwtVerifier = CognitoJwtVerifier.create({
            userPoolId: this.getUserPoolID(),
            clientId: this.getUserPoolClientId(),
            tokenUse: "id",
        });

        try {
            const payload = await jwtVerifier.verify(idToken, {
                clientId: this.getUserPoolClientId(),
            });
            return payload as unknown as DecodedIdToken;
        } catch (error: unknown) {
            if (error instanceof Error) {
                throw new Error(`Invalid ID-Token: ${error.message}`);
            }
            throw new Error('Invalid ID-Token: Unknown error');
        }
    }

    async getCredentials(idToken: string): Promise<any> {
        // validate the token
        const jwtVerifier = CognitoJwtVerifier.create({
            userPoolId: this.getUserPoolID(),
            clientId: this.getUserPoolClientId(),
            tokenUse: null,
        });

        try {
            await jwtVerifier.verify(idToken, {
                clientId: this.getUserPoolClientId(),
            });
        } catch (e) {
            throw new Error(`Invalid ID-Token: ${e}`);
        }

        const identityPoolId = this.getIdentityPoolId();
        const providerName = `cognito-idp.us-east-1.amazonaws.com/${this.getUserPoolID()}`;
        const identityInput = {
            IdentityPoolId: identityPoolId,
            Logins: {
                [ providerName ]: idToken,
            },
        };

        const identityCommand = new GetIdCommand(identityInput);
        const identityResponse = await this.identityClient.send(identityCommand);
        const identityID = identityResponse.IdentityId;

        const credentialInput = {
            IdentityId: identityID,
            Logins: {
                [ providerName ]: idToken,
            },
        };

        const command = new GetCredentialsForIdentityCommand(credentialInput);
        return await this.identityClient.send(command);
    }

    async getSocialSignInConfig(redirectUri: string): Promise<SocialSignInConfigs> {
        const userPoolClientId = this.getUserPoolClientId();
        const domain = this.getAuthDomain();
        
        // Ensure we have the required configuration
        if (!domain) {
            throw new Error('Cognito domain is not configured');
        }

        const configs: SocialSignInConfigs = {};

        // Common parameters for all providers
        const baseParams = {
            client_id: userPoolClientId,
            response_type: 'code',
            scope: 'email openid profile',
            redirect_uri: redirectUri,
        };

        // Configure Google provider if enabled
        if (this.isProviderEnabled('Google')) {
            const googleParams = new URLSearchParams({
                ...baseParams,
                identity_provider: 'Google'
            });
            const encodedParams = googleParams.toString().replace(/\+/g, '%20');
            
            configs.Google = {
                authorizationUrl: `https://${domain}/oauth2/authorize?${encodedParams}`,
                clientId: userPoolClientId,
                redirectUri: redirectUri,
                grantType: 'authorization_code'
            };
        }

        // Configure Facebook provider if enabled
        if (this.isProviderEnabled('Facebook')) {
            const facebookParams = new URLSearchParams({
                ...baseParams,
                identity_provider: 'Facebook'
            });
            const encodedParams = facebookParams.toString().replace(/\+/g, '%20');
            
            configs.Facebook = {
                authorizationUrl: `https://${domain}/oauth2/authorize?${encodedParams}`,
                clientId: userPoolClientId,
                redirectUri: redirectUri,
                grantType: 'authorization_code'
            };
        }

        return configs;
    }

    private getSupportedSocialProviders(): string[] {
        return [...SOCIAL_PROVIDERS];
    }

    private isProviderEnabled(provider: SocialProvider): boolean {
        // This is a simple check - you might want to enhance this based on your configuration
        const supportedProviders = this.getSupportedSocialProviders();
        return supportedProviders.includes(provider);
    }

    async initiateSocialSignIn(provider: SocialProvider, redirectUri: string): Promise<string> {
        const configs = await this.getSocialSignInConfig(redirectUri);
        const providerConfig = configs[provider];
        
        if (!providerConfig) {
            throw new Error(`Social provider ${provider} is not configured`);
        }

        return providerConfig.authorizationUrl;
    }

    async completeSocialSignIn(provider: SocialProvider, code: string, redirectUri: string): Promise<SocialSignInResult> {
        const userPoolClientId = this.getUserPoolClientId();
        const domain = this.getAuthDomain();

        if (!domain || !userPoolClientId) {
            throw new Error('Missing required configuration: domain or userPoolClientId');
        }

        // Exchange the authorization code for tokens using Cognito's OAuth endpoint
        const tokenEndpoint = `https://${domain}/oauth2/token`;
        const params = new URLSearchParams({
            grant_type: 'authorization_code',
            client_id: userPoolClientId,
            code: code,
            redirect_uri: redirectUri,
        });

        try {
            const response = await fetch(tokenEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: params.toString(),
            });

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Token exchange failed: ${errorText}`);
            }

            const tokens = await response.json();

            // Pre-check: ensure Cognito user exists before proceeding
            try {
                // Decode the ID token to extract the Cognito username
                const decoded = await this.verifyIdToken(tokens.id_token);
                const username = (decoded['cognito:username'] as string) || decoded.sub;
                const email = decoded.email;
                // Link the social identity using the existing method; this will raise if user does not exist
                await this.linkSocialProvider(email, username, provider);
            } catch (e: any) {
                throw new Error('No user found. Please sign up before using social login.');
            }

            // Map the OAuth response to our expected format
            const result: SocialSignInResult = {
                AccessToken: tokens.access_token,
                IdToken: tokens.id_token,
                RefreshToken: tokens.refresh_token,
                TokenType: tokens.token_type,
                ExpiresIn: tokens.expires_in,
                provider,
                isNewUser: false
            };

            return result;
        } catch (error: any) {
            throw new Error(`Failed to complete social sign-in: ${error.message}`);
        }
    }

    async socialSignup(provider: SocialProvider, code: string, redirectUri: string, userAttributes: Array<{ Name: string, Value: string }> = []): Promise<SocialSignInResult> {
        const userPoolClientId = this.getUserPoolClientId();
        const domain = this.getAuthDomain();

        if (!domain || !userPoolClientId) {
            throw new Error('Missing required configuration: domain or userPoolClientId');
        }

        // Exchange the authorization code for tokens using Cognito's OAuth endpoint
        const tokenEndpoint = `https://${domain}/oauth2/token`;
        const params = new URLSearchParams({
            grant_type: 'authorization_code',
            client_id: userPoolClientId,
            code: code,
            redirect_uri: redirectUri,
        });

        try {
            const response = await fetch(tokenEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: params.toString(),
            });

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Token exchange failed: ${errorText}`);
            }

            const tokens = await response.json();

            // Check if user already exists
            try {
                // Decode the ID token to extract the Cognito username
                const decoded = await this.verifyIdToken(tokens.id_token);
                const username = (decoded['cognito:username'] as string) || decoded.sub;
                // Try to get the user - if this succeeds, user already exists
                await this.identityProviderClient.send(
                    new AdminGetUserCommand({
                        UserPoolId: this.getUserPoolID(),
                        Username: username,
                    })
                );
                throw new Error('User already exists. Please sign in instead.');
            } catch (e: any) {
                // If AdminGetUserCommand fails with UserNotFoundException, we can proceed with signup
                if (e.name !== 'UserNotFoundException') {
                    throw e;
                }
            }

            // Update user attributes if provided
            if (userAttributes.length > 0) {
                const decoded = await this.verifyIdToken(tokens.id_token);
                const username = (decoded['cognito:username'] as string) || decoded.sub;
                
                await this.identityProviderClient.send(
                    new AdminUpdateUserAttributesCommand({
                        UserPoolId: this.getUserPoolID(),
                        Username: username,
                        UserAttributes: userAttributes,
                    })
                );
            }

            // Map the OAuth response to our expected format
            const result: SocialSignInResult = {
                AccessToken: tokens.access_token,
                IdToken: tokens.id_token,
                RefreshToken: tokens.refresh_token,
                TokenType: tokens.token_type,
                ExpiresIn: tokens.expires_in,
                provider,
                isNewUser: true
            };

            return result;
        } catch (error: any) {
            throw new Error(`Failed to complete social signup: ${error.message}`);
        }
    }

    async linkSocialProvider(email: string, username: string, provider: SocialProvider): Promise<void> {
        const userPoolId = this.getUserPoolID();
        try {
            const listUsersResult = await this.identityProviderClient.send(
                new ListUsersCommand({
                    UserPoolId: userPoolId,
                    Filter: `email = "${email}"`,
                    Limit: 10,
                })
            );
            if (!listUsersResult.Users) {
                throw new Error('No user found with this email');
            }
            // find the native user
            const nativeUser = listUsersResult.Users.find(
                u => u.Username && !u.Username.startsWith(provider) && u.UserStatus !== 'EXTERNAL_PROVIDER'
            );
            if (!nativeUser) {
                throw new Error('No User found with this email. Please sign up before using social login.');
            }
            // check if the user is already linked to this provider (by federated username in identities)
            const identitiesAttr = nativeUser.Attributes?.find(attr => attr.Name === 'identities')?.Value;
            let alreadyLinked = false;
            if (identitiesAttr) {
                try {
                    const identities = JSON.parse(identitiesAttr);
                    alreadyLinked = Array.isArray(identities) && identities.some(
                        (identity: any) => identity.userId === username
                    );
                } catch (e) {
                    alreadyLinked = false;
                }
            }
            if (alreadyLinked) {
                this.logger.info('social provider already linked for the user', nativeUser.Username!, username, provider);
                return;
            }
            this.logger.debug('linking social provider for the user', nativeUser.Username!, username, provider);
            await this.identityProviderClient.send(
                new AdminLinkProviderForUserCommand({
                    UserPoolId: userPoolId,
                    DestinationUser: {
                        ProviderName: 'Cognito',
                        ProviderAttributeValue: nativeUser.Username!,
                    },
                    SourceUser: {
                        ProviderName: provider,
                        ProviderAttributeName: 'Cognito_Subject',
                        ProviderAttributeValue: username,
                    },
                })
            );
            this.logger.debug('linked social provider for the user, checking the user groups');
            // sync the user groups for the linked user
            const groups = await this.getUserGroupNames(nativeUser.Username!);
            this.logger.debug('syncing user groups for the linked user', nativeUser.Username!, groups);
            await this.setUserGroups(username, groups, false);

        } catch (e: any) {
            this.logger.error('Failed to link social provider', e);
            throw new Error('Failed to link social provider', e);
        }
    }

    async unlinkSocialProvider(accessToken: string, provider: SocialProvider): Promise<void> {
        const userPoolId = this.getUserPoolID();
        // First, verify the user's identity with the access token
        const userResult = await this.identityProviderClient.send(
            new GetUserCommand({
                AccessToken: accessToken,
            })
        );

        // Then unlink the provider using the admin API
        await this.identityProviderClient.send(
            new AdminDisableProviderForUserCommand({
                UserPoolId: userPoolId,
                User: {
                    ProviderAttributeName: 'Cognito_Subject',
                    ProviderName: provider,
                    ProviderAttributeValue: userResult.Username!,
                },
            })
        );
    }

    // Utility functions
    private getIdentityPoolId() {
        const identityPoolId = resolveEnvValueFor({key: 'identityPoolID'}) || '';
        if (!identityPoolId) {
            throw new Error('Identity pool ID is not configured');
        }
        return identityPoolId;
    }

    private getUserPoolClientId() {
        const clientId = resolveEnvValueFor({key: 'userPoolClientID'}) || '';
        if (!clientId) {
            throw new Error('User pool client ID is not configured');
        }
        return clientId;
    }

    private getUserPoolID() {
        const userPoolId = resolveEnvValueFor({key: 'userPoolID'}) || '';
        if (!userPoolId) {
            throw new Error('User pool ID is not configured');
        }
        return userPoolId;
    }

    private getAuthDomain(): string {
        return resolveEnvValueFor({key: 'authDomain'}) || '';
    }

    async getUser(usernameOrEmail: string): Promise<UserDetails> {
        const userPoolId = this.getUserPoolID();
        
        // First try to get user directly by username
        try {
            const result = await this.identityProviderClient.send(
                new AdminGetUserCommand({
                    UserPoolId: userPoolId,
                    Username: usernameOrEmail,
                })
            );

            return {
                Username: result.Username!,
                email: result.UserAttributes?.find(attr => attr.Name === 'email')?.Value,
                Enabled: result.Enabled,
                UserStatus: result.UserStatus,
                Attributes: result.UserAttributes?.map(attr => ({
                    Name: attr.Name || '',
                    Value: attr.Value || ''
                })),
            };
        } catch (error: any) {
            // If not found by username and input looks like email, try searching by email
            if (error.name === 'UserNotFoundException' && this.isValidEmail(usernameOrEmail)) {
                const result = await this.identityProviderClient.send(
                    new ListUsersCommand({
                        UserPoolId: userPoolId,
                        Filter: `email = "${usernameOrEmail}"`,
                        Limit: 1,
                    })
                );

                if (!result.Users || result.Users.length === 0) {
                    throw new Error('User not found');
                }

                const user = result.Users[0];
                return {
                    Username: user.Username!,
                    email: user.Attributes?.find(attr => attr.Name === 'email')?.Value,
                    Enabled: user.Enabled,
                    UserStatus: user.UserStatus,
                    Attributes: user.Attributes?.map(attr => ({
                        Name: attr.Name || '',
                        Value: attr.Value || ''
                    })),
                };
            }
            throw error;
        }
    }

    async getCurrentUser(accessToken: string): Promise<UserDetails> {
        try {
            const result = await this.identityProviderClient.send(
                new GetUserCommand({
                    AccessToken: accessToken,
                })
            );

            return {
                Username: result.Username!,
                email: result.UserAttributes?.find(attr => attr.Name === 'email')?.Value,
                Enabled: true, // GetUser only returns data for enabled users
                UserStatus: 'CONFIRMED', // Users with valid access tokens are confirmed
                Attributes: result.UserAttributes?.map(attr => ({
                    Name: attr.Name || '',
                    Value: attr.Value || ''
                })),
            };
        } catch (error: any) {
            throw new Error(`Failed to get current user: ${error.message}`);
        }
    }

}
