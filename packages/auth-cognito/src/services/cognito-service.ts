import { CognitoIdentityProviderClient, SignUpCommand, InitiateAuthCommand, ConfirmSignUpCommand, GlobalSignOutCommand, ChangePasswordCommand, ForgotPasswordCommand, ConfirmForgotPasswordCommand, AdminAddUserToGroupCommand, AdminRemoveUserFromGroupCommand, AdminListGroupsForUserCommand, AdminSetUserPasswordCommand, AdminResetUserPasswordCommand, AdminCreateUserCommand, DeliveryMediumType, AdminUpdateUserAttributesCommand, ChallengeName, AuthenticationResultType, ChallengeNameType, RespondToAuthChallengeCommand } from "@aws-sdk/client-cognito-identity-provider";
import { CognitoIdentityClient, GetIdCommand, GetCredentialsForIdentityCommand } from "@aws-sdk/client-cognito-identity";
import { CreateUserOptions, IAuthService, SignInResult, UpdateUserAttributeOptions } from "../interfaces";
import { CognitoJwtVerifier } from "aws-jwt-verify";
import { resolveEnvValueFor } from "@ten24group/fw24";

export class CognitoService implements IAuthService {
    
    private identityProviderClient = new CognitoIdentityProviderClient({});
    private identityClient = new CognitoIdentityClient({});

    async signup(username: string, password: string): Promise<void> {
        const userPoolClientId = this.getUserPoolClientId();

        const userAttributes = [
            {
                Name: 'email',
                Value: username,
            },
        ];

        await this.identityProviderClient.send(
            new SignUpCommand({
                ClientId: userPoolClientId,
                Username: username,
                Password: password,
                UserAttributes: userAttributes,
            })
        );
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

        if(result.ChallengeName){
            return {
                challengeName: result.ChallengeName,
                challengeParameters: result.ChallengeParameters,
            }
        }

        return result.AuthenticationResult!;
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

    async getLoginOptions(username: string): Promise<ChallengeNameType[]|undefined> {
        const result = await this.identityProviderClient.send(
            new InitiateAuthCommand({
                AuthFlow: 'USER_AUTH',
                ClientId: this.getUserPoolClientId(),
                AuthParameters: {
                    USERNAME: username
                }
            })
        );

        return result.AvailableChallenges;
    }

    async initiateOtpAuth(username: string): Promise<{ session: string }> {
        const result = await this.identityProviderClient.send(
            new InitiateAuthCommand({
                AuthFlow: 'CUSTOM_AUTH',
                ClientId: this.getUserPoolClientId(),
                AuthParameters: {
                    USERNAME: username,
                    CHALLENGE_NAME: 'CUSTOM_CHALLENGE'
                }
            })
        );

        if (!result.Session) {
            throw new Error('Failed to initiate OTP authentication');
        }

        return { session: result.Session };
    }

    async respondToOtpChallenge(username: string, session: string, code: string): Promise<SignInResult> {
        const result = await this.identityProviderClient.send(
            new RespondToAuthChallengeCommand({
                ClientId: this.getUserPoolClientId(),
                ChallengeName: 'CUSTOM_CHALLENGE',
                Session: session,
                ChallengeResponses: {
                    USERNAME: username,
                    ANSWER: code
                }
            })
        );

        if (result.ChallengeName) {
            return {
                challengeName: result.ChallengeName,
                challengeParameters: result.ChallengeParameters
            };
        }

        if (!result.AuthenticationResult) {
            throw new Error('Authentication failed');
        }

        return result.AuthenticationResult;
    }

    async changePassword(accessToken: string, oldPassword: string, newPassword: string): Promise<void> {
        await this.identityProviderClient.send(
            new ChangePasswordCommand({
                AccessToken: accessToken,
                PreviousPassword: oldPassword,
                ProposedPassword: newPassword,
            })
        );
    }

    async createUser(options: CreateUserOptions) {
        const { username, tempPassword, attributes = [] } = options;
        
        await this.identityProviderClient.send(
            new AdminCreateUserCommand({
                Username: username,
                UserPoolId: this.getUserPoolID(),
                TemporaryPassword: tempPassword,
                DesiredDeliveryMediums: [DeliveryMediumType.EMAIL],
                MessageAction: "SUPPRESS",
                UserAttributes: attributes,
            })
        );
    }

    async setPassword(username: string, password: string, forceChangePassword=true ){
        await this.identityProviderClient.send(
            new AdminSetUserPasswordCommand({
                Username: username,
                Password: password,
                Permanent: !forceChangePassword,
                UserPoolId: this.getUserPoolID(),
            })
        );
    }

    async resetPassword(username: string){
        await this.identityProviderClient.send(
            new AdminResetUserPasswordCommand({
                Username: username,
                UserPoolId: this.getUserPoolID(),
            })
        );
    }


    async forgotPassword(username: string): Promise<void> {
        await this.identityProviderClient.send(
            new ForgotPasswordCommand({
                ClientId: this.getUserPoolClientId(),
                Username: username
            })
        );
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

        return groupsList.Groups?.map( g => g.GroupName ?? '' ) ?? [];
    }

    async setUserGroups(username: string, newGroups: string[]): Promise<void> {
        const existingUserGroups = await this.getUserGroupNames(username);

        const promises = [];

        // collect only the new groups to be added
        for(const group of newGroups){
            if(!existingUserGroups.includes(group)){
                promises.push(this.addUserToGroup(username, group))
            }
        }

        // collect any existing-groups which are not part of new-groups for removal
        for(const group of existingUserGroups){
            if(!newGroups.includes(group)){
                promises.push(this.removeUserFromGroup(username, group))
            }
        }

        await Promise.all(promises);
    }

    async updateUserAttributes( options: UpdateUserAttributeOptions): Promise<void> {
        const { username, attributes } = options;

        await this.identityProviderClient.send(
            new AdminUpdateUserAttributesCommand({
                Username: username,
                UserPoolId: this.getUserPoolID(),
                UserAttributes: attributes,
            })
        );

    }

    async getCredentials(idToken: string): Promise<any> {
        // validate the token
        const jwtVerifier = CognitoJwtVerifier.create({
            userPoolId: this.getUserPoolID(),
            clientId: this.getUserPoolClientId(),
            tokenUse: null,
        });

        try {
            await jwtVerifier.verify(idToken);
        } catch {
            throw new Error(`Invalid ID-Token: ${idToken}`);
        }

        const providerName = `cognito-idp.us-east-1.amazonaws.com/${this.getUserPoolID()}`;
        const identityInput = {
            IdentityPoolId: this.getIdentityPoolId(),
            Logins: {
                [providerName]: idToken,
            },
        };

        const identityCommand = new GetIdCommand(identityInput);
        const identityResponse = await this.identityClient.send(identityCommand);
        const identityID = identityResponse.IdentityId;

        const credentialInput = {
            IdentityId: identityID,
            Logins: {
                [providerName]: idToken,
            },
        };

        const command = new GetCredentialsForIdentityCommand(credentialInput);
        return await this.identityClient.send(command);
    }

    // Utility functions
    private getIdentityPoolId() {
        return resolveEnvValueFor({key: 'identityPoolID'}) || '';
    }

    private getUserPoolClientId() {
        return resolveEnvValueFor({key: 'userPoolClientID'}) || '';
    }

    private getUserPoolID() {
        return resolveEnvValueFor({key: 'userPoolID'}) || '';
    }
}
