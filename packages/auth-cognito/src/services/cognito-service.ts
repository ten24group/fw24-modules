import { CognitoIdentityProviderClient, SignUpCommand, InitiateAuthCommand, ConfirmSignUpCommand, GlobalSignOutCommand, ChangePasswordCommand, ForgotPasswordCommand, ConfirmForgotPasswordCommand, AdminAddUserToGroupCommand, AdminRemoveUserFromGroupCommand, AdminListGroupsForUserCommand, AdminSetUserPasswordCommand, AdminResetUserPasswordCommand, AdminCreateUserCommand, DeliveryMediumType, AdminUpdateUserAttributesCommand, ChallengeName, AuthenticationResultType, ChallengeNameType, ListUsersCommand } from "@aws-sdk/client-cognito-identity-provider";
import { CognitoIdentityClient, GetIdCommand, GetCredentialsForIdentityCommand } from "@aws-sdk/client-cognito-identity";
import { CreateUserOptions, IAuthService, SignInResult, UpdateUserAttributeOptions } from "../interfaces";
import { CognitoJwtVerifier } from "aws-jwt-verify";
import { createLogger, resolveEnvValueFor } from "@ten24group/fw24";

export class CognitoService implements IAuthService {
    private readonly logger = createLogger(CognitoService);

    private identityProviderClient = new CognitoIdentityProviderClient({});
    private identityClient = new CognitoIdentityClient({});

    // Event object is the event passed to Lambda
    async getUserByUserSub(userSub: string) {

        let result = await this.identityProviderClient.send(new ListUsersCommand({
            UserPoolId: this.getUserPoolID(),
            Filter: `sub = "${userSub}"`,
            Limit: 1
        }));

        const user = result.Users?.length ? result.Users[ 0 ] : undefined;

        return user;
    }

    async signup(username: string, password: string): Promise<void> {
        this.logger.info(`Signing-up user: ${username}`);

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
        this.logger.info(`Signing-in user: ${username}`);
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
                challengeName: result.ChallengeName,
                challengeParameters: result.ChallengeParameters,
            }
        }

        return result.AuthenticationResult!;
    }

    async signout(accessToken: string): Promise<void> {
        this.logger.info(`Signing-out user`);
        await this.identityProviderClient.send(
            new GlobalSignOutCommand({
                AccessToken: accessToken,
            })
        );
    }

    async verify(username: string, code: string): Promise<void> {
        this.logger.info(`Verifying user: ${username}`);
        const userPoolClientId = this.getUserPoolClientId();

        await this.identityProviderClient.send(
            new ConfirmSignUpCommand({
                ClientId: userPoolClientId,
                Username: username,
                ConfirmationCode: code,
            })
        );
    }

    async changePassword(accessToken: string, oldPassword: string, newPassword: string): Promise<void> {
        this.logger.info(`Changing password for user: ${accessToken}`);
        await this.identityProviderClient.send(
            new ChangePasswordCommand({
                AccessToken: accessToken,
                PreviousPassword: oldPassword,
                ProposedPassword: newPassword,
            })
        );
    }

    async createUser(options: CreateUserOptions) {
        this.logger.info(`Creating user: ${options.username}`);
        const { username, tempPassword, attributes = [] } = options;

        await this.identityProviderClient.send(
            new AdminCreateUserCommand({
                Username: username,
                UserPoolId: this.getUserPoolID(),
                TemporaryPassword: tempPassword,
                DesiredDeliveryMediums: [ DeliveryMediumType.EMAIL ],
                MessageAction: "SUPPRESS",
                UserAttributes: attributes,
            })
        );
    }

    async setPassword(username: string, password: string, forceChangePassword = true) {
        this.logger.info(`Setting password for user: ${username}`, { forceChangePassword });
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
        this.logger.info(`Resetting password for user: ${username}`);
        await this.identityProviderClient.send(
            new AdminResetUserPasswordCommand({
                Username: username,
                UserPoolId: this.getUserPoolID(),
            })
        );
    }


    async forgotPassword(username: string): Promise<void> {
        this.logger.info(`Triggering Forgot-Password flow for user: ${username}`);
        await this.identityProviderClient.send(
            new ForgotPasswordCommand({
                ClientId: this.getUserPoolClientId(),
                Username: username
            })
        );
    }

    async confirmForgotPassword(username: string, code: string, newPassword: string): Promise<void> {
        this.logger.info(`Confirming Forgot-Password flow for user: ${username}`);
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
        this.logger.info(`Adding user to group: ${groupName} for user: ${username}`);
        await this.identityProviderClient.send(
            new AdminAddUserToGroupCommand({
                UserPoolId: this.getUserPoolID(),
                GroupName: groupName,
                Username: username,
            })
        );
    }

    async removeUserFromGroup(username: string, groupName: string): Promise<void> {
        this.logger.info(`Removing user from group: ${groupName} for user: ${username}`);
        await this.identityProviderClient.send(
            new AdminRemoveUserFromGroupCommand({
                UserPoolId: this.getUserPoolID(),
                GroupName: groupName,
                Username: username,
            })
        );
    }

    async getUserGroupNames(username: string): Promise<Array<string>> {
        this.logger.info(`Getting group names for user: ${username}`);
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

    async setUserGroups(username: string, newGroups: string[]): Promise<void> {
        this.logger.info(`Setting groups for user: ${username}`);
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
            if (!newGroups.includes(group)) {
                promises.push(this.removeUserFromGroup(username, group))
            }
        }

        await Promise.all(promises);
    }

    async updateUserAttributes(options: UpdateUserAttributeOptions): Promise<void> {
        this.logger.info(`Updating user attributes for user: ${options.username}`);
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
        this.logger.info(`Getting credentials for user`);
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

    // Utility functions
    private getIdentityPoolId() {
        return resolveEnvValueFor({ key: 'identityPoolId' }) || '';
    }

    private getUserPoolClientId() {
        return resolveEnvValueFor({ key: 'userPoolClientId' }) || '';
    }

    private getUserPoolID() {
        return resolveEnvValueFor({ key: 'userPoolId' }) || '';
    }
}
