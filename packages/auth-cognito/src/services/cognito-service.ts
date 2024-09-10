import { CognitoIdentityProviderClient, SignUpCommand, InitiateAuthCommand, ConfirmSignUpCommand, GlobalSignOutCommand, ChangePasswordCommand, ForgotPasswordCommand, ConfirmForgotPasswordCommand, AdminAddUserToGroupCommand } from "@aws-sdk/client-cognito-identity-provider";
import { CognitoIdentityClient, GetIdCommand, GetCredentialsForIdentityCommand } from "@aws-sdk/client-cognito-identity";
import { IAuthService } from "../interfaces";
import { CognitoJwtVerifier } from "aws-jwt-verify";

export class CognitoService implements IAuthService {
    
    private identityProviderClient = new CognitoIdentityProviderClient({});
    private identityClient = new CognitoIdentityClient({});

    async signup(email: string, password: string): Promise<void> {
        const userPoolClientId = this.getUserPoolClientId();

        await this.identityProviderClient.send(
            new SignUpCommand({
                ClientId: userPoolClientId,
                Username: email,
                Password: password,
                UserAttributes: [
                    {
                        Name: 'email',
                        Value: email,
                    },
                ],
            })
        );
    }

    async signin(email: string, password: string): Promise<any> {
        const userPoolClientId = this.getUserPoolClientId();

        const result = await this.identityProviderClient.send(
            new InitiateAuthCommand({
                AuthFlow: 'USER_PASSWORD_AUTH',
                ClientId: userPoolClientId,
                AuthParameters: {
                    USERNAME: email,
                    PASSWORD: password,
                },
            })
        );

        return result.AuthenticationResult;
    }

    async signout(accessToken: string): Promise<void> {
        await this.identityProviderClient.send(
            new GlobalSignOutCommand({
                AccessToken: accessToken,
            })
        );
    }

    async verify(email: string, code: string): Promise<void> {
        const userPoolClientId = this.getUserPoolClientId();

        await this.identityProviderClient.send(
            new ConfirmSignUpCommand({
                ClientId: userPoolClientId,
                Username: email,
                ConfirmationCode: code,
            })
        );
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

    async forgotPassword(email: string): Promise<void> {
        await this.identityProviderClient.send(
            new ForgotPasswordCommand({
                ClientId: this.getUserPoolClientId(),
                Username: email,
            })
        );
    }

    async confirmForgotPassword(email: string, code: string, newPassword: string): Promise<void> {
        await this.identityProviderClient.send(
            new ConfirmForgotPasswordCommand({
                ClientId: this.getUserPoolClientId(),
                Username: email,
                ConfirmationCode: code,
                Password: newPassword,
            })
        );
    }

    async addUserToGroup(email: string, groupName: string): Promise<void> {
        await this.identityProviderClient.send(
            new AdminAddUserToGroupCommand({
                UserPoolId: this.getUserPoolID(),
                GroupName: groupName,
                Username: email,
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
        return process.env['identityPoolID'] || '';
    }

    private getUserPoolClientId() {
        return process.env['userPoolClientID'] || '';
    }

    private getUserPoolID() {
        return process.env['userPoolID'] || '';
    }
}
