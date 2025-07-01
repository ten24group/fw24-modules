import { AdminAddUserToGroupCommand, CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { resolveEnvValueFor } from '@ten24group/fw24';
import { request } from 'http';
import { CUSTOM_MESSAGE_ADMIN_CREATE_USER, CUSTOM_MESSAGE_AUTHENTICATE, CUSTOM_MESSAGE_FORGOT_PASSWORD, CUSTOM_MESSAGE_RESEND_CODE, CUSTOM_MESSAGE_SIGN_UP, CUSTOM_MESSAGE_UPDATE_USER_ATTRIBUTE, CUSTOM_MESSAGE_VERIFY_USER_ATTRIBUTE, CUSTOM_SUBJECT_ADMIN_CREATE_USER, CUSTOM_SUBJECT_AUTHENTICATE, CUSTOM_SUBJECT_FORGOT_PASSWORD, CUSTOM_SUBJECT_RESEND_CODE, CUSTOM_SUBJECT_SIGN_UP, CUSTOM_SUBJECT_UPDATE_USER_ATTRIBUTE, CUSTOM_SUBJECT_VERIFY_USER_ATTRIBUTE } from '../const';

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

	console.log("custom message event: ", event);
	
    let emailSubject: string | null = null;
    let emailMessage: string | null = null;

    if(triggerSource === "CustomMessage_ForgotPassword") {

        emailSubject = resolveEnvValueFor({key: CUSTOM_SUBJECT_FORGOT_PASSWORD }) || `Forgot Password Request`;
        emailMessage = resolveEnvValueFor({key: CUSTOM_MESSAGE_FORGOT_PASSWORD }) || `To change your password, please use the following code: ${codeParameter}`;

    } else if(triggerSource === "CustomMessage_UpdateUserAttribute") {
		
		emailSubject = resolveEnvValueFor({key: CUSTOM_SUBJECT_UPDATE_USER_ATTRIBUTE }) || null;
        emailMessage = resolveEnvValueFor({key: CUSTOM_MESSAGE_UPDATE_USER_ATTRIBUTE }) || null;  

	} else if(triggerSource === "CustomMessage_VerifyUserAttribute") {

		emailSubject = resolveEnvValueFor({key: CUSTOM_SUBJECT_VERIFY_USER_ATTRIBUTE }) || 'Verify Your Account';
    emailMessage = resolveEnvValueFor({key: CUSTOM_MESSAGE_VERIFY_USER_ATTRIBUTE }) || `Your verification code is: ${codeParameter}`;

	} else if(triggerSource === "CustomMessage_Authentication") {
		const uiBaseUrl = resolveEnvValueFor({ key: 'uiBaseUrl' });
		const session = event.request.session;
		const username = event.userName;

		if (!uiBaseUrl || !session || !codeParameter || !username) {
				console.error("Missing required parameters to generate magic link.");
				// Do not modify the event, let Cognito handle the error
				return event;
		}
		
		// Construct the magic link
		const magicLink = `${uiBaseUrl}/magic-link-confirm?session=${session}&code=${codeParameter}&username=${username}`;

		emailSubject = resolveEnvValueFor({key: CUSTOM_SUBJECT_AUTHENTICATE}) || 'Your Magic Sign-In Link';
		emailMessage = resolveEnvValueFor({key: CUSTOM_MESSAGE_AUTHENTICATE }) || `
				<html>
						<body>
								<p>Hello,</p>
								<p>Please click the link below to sign in:</p>
								<a href="${magicLink}">Sign In</a>
								<p>This link will expire in a few minutes.</p>
						</body>
				</html>
		`;

	} else if(triggerSource === "CustomMessage_SignUp") {

		emailSubject = resolveEnvValueFor({key: CUSTOM_SUBJECT_SIGN_UP }) || 'Welcome! Please Verify Your Email';
    emailMessage = resolveEnvValueFor({key: CUSTOM_MESSAGE_SIGN_UP }) || null;  

  } else if(triggerSource === "CustomMessage_AdminCreateUser") {

		emailSubject = resolveEnvValueFor({key: CUSTOM_SUBJECT_ADMIN_CREATE_USER }) || null;
    emailMessage = resolveEnvValueFor({key: CUSTOM_MESSAGE_ADMIN_CREATE_USER }) || null; 

	} else if(triggerSource === "CustomMessage_ResendCode") {

		emailSubject = resolveEnvValueFor({key: CUSTOM_SUBJECT_RESEND_CODE }) || null;
    emailMessage = resolveEnvValueFor({key: CUSTOM_MESSAGE_RESEND_CODE }) || null;  
	}
	
    event.response.smsMessage = emailMessage;
    event.response.emailMessage = emailMessage;
    event.response.emailSubject = emailSubject;

    return event;
}