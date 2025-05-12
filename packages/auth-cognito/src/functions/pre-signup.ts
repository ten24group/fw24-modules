import { CognitoIdentityProviderClient, ListUsersCommand } from "@aws-sdk/client-cognito-identity-provider";
import { resolveEnvValueFor } from "@ten24group/fw24";

export const handler = async (event: any, context: any, callback: any) => {
    const autoVerifyUser = resolveEnvValueFor({key: 'autoVerifyUser' }) === 'true';
    const socialProviders = resolveEnvValueFor({key: 'socialProviders' }) === 'true';

    // auto verify user
    if (autoVerifyUser) {
        event.response.autoConfirmUser = true;
        event.response.autoVerifyEmail = true;
    }

    // check if user exists for social signup
    if (socialProviders && event.triggerSource === 'PreSignUp_ExternalProvider') {
        const identityProviderClient = new CognitoIdentityProviderClient({});
        const email = event.request.userAttributes.email!;
        const existing = await identityProviderClient
          .send(new ListUsersCommand({
            UserPoolId: event.userPoolId!,
            Filter:    `email = "${email}"`,
            Limit:     1,
          }));
        if (existing.Users?.length === 0) {
            // Reject brand-new social signups outright:
            throw new Error('Account not found. Please sign up first.');
        }
    }
    callback(null, event);
};
