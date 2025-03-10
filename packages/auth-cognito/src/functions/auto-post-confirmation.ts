import { AdminAddUserToGroupCommand, CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { resolveEnvValueFor } from '@ten24group/fw24';

export const handler = async (event: any) => {
    console.log('::handler:: Event: ', event);
    const username = event.userName;
    const userPoolID = event.userPoolId;
    const autoUserSignupGroups = getAutoUserSignupGroups().split(',');
    const identityProviderClient = new CognitoIdentityProviderClient({});

    //add user to default groups
    for (const groupName of autoUserSignupGroups) {
        await identityProviderClient.send(
            new AdminAddUserToGroupCommand({
                UserPoolId: userPoolID,
                GroupName: groupName,
                Username: username,
            }),
        );
    }
    return event;
}

function getAutoUserSignupGroups() {
    return resolveEnvValueFor({key: 'autoSignupGroups' }) || '';
}