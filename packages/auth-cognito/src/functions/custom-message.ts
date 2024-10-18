import { AdminAddUserToGroupCommand, CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { resolveEnvValueFor } from '@ten24group/fw24';
import { request } from 'http';
import { CUSTOM_MESSAGE_ADMIN_CREATE_USER, CUSTOM_MESSAGE_FORGOT_PASSWORD, CUSTOM_SUBJECT_ADMIN_CREATE_USER, CUSTOM_SUBJECT_FORGOT_PASSWORD } from '../const';

/*
{
	"version": "1",
	"region": "us-west-2",
	"userPoolId": "us-west-2_EXAMPLE",
	"userName": "test-user",
	"callerContext": {
		"awsSdkVersion": "aws-sdk-unknown-unknown",
		"clientId": "1example23456789"
	},
	"triggerSource": "CustomMessage_SignUp",
	"request": {
		"userAttributes": {
			"sub": "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111",
			"cognito:user_status": "CONFIRMED",
			"email_verified": "true",
			"phone_number_verified": "true",
			"phone_number": "+12065551212",
			"email": "test-user@example.com"
		},
		"codeParameter": "{####}",
		"linkParameter": "{##Click Here##}",
		"usernameParameter": "None"
	},
	"response": {
		"smsMessage": "None",
		"emailMessage": "None",
		"emailSubject": "None"
	}
}

*/

export const handler = async (event: any) => {

    const { triggerSource, request: { userAttributes, clientMetadata, usernameParameter, linkParameter, codeParameter } } = event;

    // NOTE: This is where you would customize the message for the user
    // see https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-custom-message.html#cognito-user-pools-lambda-trigger-syntax-custom-message-trigger-source

    let smsMessage: string | null = null;
    let emailSubject: string | null = null;
    let emailMessage: string | null = null;

    if(triggerSource === "CustomMessage_ForgotPassword") {

        emailSubject = resolveEnvValueFor({key: CUSTOM_SUBJECT_FORGOT_PASSWORD }) || `Forgot Password Request`;
        emailMessage = resolveEnvValueFor({key: CUSTOM_MESSAGE_FORGOT_PASSWORD }) || `To change your password, please use the following code: ${codeParameter}`;  
        smsMessage = emailMessage;

    } else if(triggerSource === "CustomMessage_UpdateUserAttribute") {
    } else if(triggerSource === "CustomMessage_VerifyUserAttribute") {
    } else if(triggerSource === "CustomMessage_Authentication") {
    } else if(triggerSource === "CustomMessage_SignUp") {
        // TODO: 
    } else if(triggerSource === "CustomMessage_AdminCreateUser") {
    } else if(triggerSource === "CustomMessage_ResendCode") {
    }

    event.response.smsMessage = smsMessage;
    event.response.emailMessage = emailMessage;
    event.response.emailSubject = emailSubject;

    return event;
}