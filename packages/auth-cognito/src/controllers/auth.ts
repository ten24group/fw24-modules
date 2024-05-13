import { Controller, APIController, Request, Response, Post, Authorizer, TestComplexValidationResult, InputValidationRule  } from '@ten24group/fw24';
import { CognitoJwtVerifier } from "aws-jwt-verify";

// import cognito client
import { CognitoIdentityProviderClient, SignUpCommand, InitiateAuthCommand, ConfirmSignUpCommand, GlobalSignOutCommand, ChangePasswordCommand, ForgotPasswordCommand, ConfirmForgotPasswordCommand, AdminAddUserToGroupCommand } from "@aws-sdk/client-cognito-identity-provider";
import { CognitoIdentityClient, GetIdCommand, GetCredentialsForIdentityCommand } from "@aws-sdk/client-cognito-identity";

const identityProviderClient = new CognitoIdentityProviderClient({});
const identityClient = new CognitoIdentityClient({});

const customPasswordValidator = (inputValue: any): TestComplexValidationResult => {
	const result: TestComplexValidationResult = {
		pass: true
	};

	const pattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@.#$!%*?&])[A-Za-z\d@.#$!^%*?&]{8,20}$/
	
	result.pass = pattern.test(inputValue);

	if(!result.pass){

		/*
			- At least one lowercase alphabet i.e. [a-z]
			- At least one uppercase alphabet i.e. [A-Z]
			- At least one Numeric digit i.e. [0-9]
			- At least one special character i.e. [`@`, `$`, `.`, `#`, `!`, `%`, `*`, `?`, `&`, `^`]
			- Also, the total length must be in the range [8-20]
		*/

		const expected: Array<string> = [];

		if (!/[a-z]/.test(inputValue)) {
			expected.push('one lowercase alphabet');
		}
		if (!/[A-Z]/.test(inputValue)){
			expected.push('one uppercase alphabet');
		}
		if (!/[\d]/.test(inputValue)){
			expected.push('one Numeric digit');
		}
		if (!/[!@#$%^&*.?]/.test(inputValue)){
			expected.push('one special character');
		}

		const strengths = ["Good", "Medium strong", "Weak", "very Weak" ]; 

		result.received = [ '*'.repeat(inputValue?.length ?? 0 ), strengths[expected?.length ] ];
		result.expected = [ 'at least', expected.join(', ')];

		result.customMessageId = "validation.http.body.password.pattern.validator";
	}

	return result;
}

type EmailAndPassword = {
	email: string, 
	password: string,
}

const emailAndPasswordValidations: InputValidationRule<EmailAndPassword> = {
	email: {
		required: true,
		datatype: 'email',
	}, 
	password: {
		required: true,
		/*
			minLength: 8,
			maxLength: 20,
			pattern: {
				validator: (inputVal: any) => Promise.resolve(customPasswordValidator(inputVal)),
			}
		*/
	}
} as const;

@Controller('mauth', { 
	authorizer: [{
		name: 'authmodule', type: 'NONE'
	}],
	env: [
		{ name: 'userPoolClientID', prefix: 'authmodule' },
		{ name: 'userPoolID', prefix: 'authmodule' },
		{ name: 'identityPoolID', prefix: 'authmodule' }
	]
})
export class AuthController extends APIController {	
	
	async initialize() {
        // register DI factories
        return Promise.resolve();
    }

	/*
		protected getOverriddenHttpRequestValidationErrorMessages(): Promise<Map<string, string>> {
			return Promise.resolve(new Map(
				Object.entries({
					"validation.http.body.password.pattern.validator": "Password '{received}' is '{refinedReceived}'; Please add {validationName} {validationValue}",
					"validation.http.body.newPassword.pattern.validator": "New password '{received}' is '{refinedReceived}'; Please add {validationName} {validationValue}",
				})
			))
		}
	*/
	/*
	Cognito signup, signin and verify email methods
	*/
	@Post('/signup', { validations: emailAndPasswordValidations } )
	async signup(req: Request, res: Response) {
		
		const {email, password} = req.body as EmailAndPassword;

		const userPoolClientId = this.getUserPoolClientId();

		await identityProviderClient.send(
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
			}),
		);
		
		return res.json({
			message: 'User Signed Up'
		});
	}

	@Post('/signin', { validations: emailAndPasswordValidations } )
	async signin(req: Request, res: Response) {
		
		const {email, password} = req.body as EmailAndPassword;

		const userPoolClientId = this.getUserPoolClientId();

		const result = await identityProviderClient.send(
			new InitiateAuthCommand({
				AuthFlow: 'USER_PASSWORD_AUTH',
				ClientId: userPoolClientId,
				AuthParameters: {
					USERNAME: email,
					PASSWORD: password,
				},
			}),
		);

		const idToken = result.AuthenticationResult?.IdToken;
		
		if (idToken === undefined) {
			return res.status(401).json({
				message: 'Authentication failed'
			});
		}

		return res.json(result.AuthenticationResult);
	}

	@Post('/signout', {
		validations: { accessToken: { required: true } }
	})
	async signout(req: Request, res: Response) {
		const {accessToken} = req.body as { accessToken: string };

		const result = await identityProviderClient.send(
			new GlobalSignOutCommand({
				AccessToken: accessToken,
			}),
		);
		this.logger.debug('result', result);

		return res.json({
			message: 'User logged out'
		});
	}

	@Post('/verify', {
		validations: {
			code: { required: true },
			email: { required: true, datatype: 'email' },
		}
	})
	async verify(req: Request, res: Response) {
		const {email, code} = req.body as { email?: string; code?: string };
		const userPoolClientId = this.getUserPoolClientId();

		const result = await identityProviderClient.send(
			new ConfirmSignUpCommand({
				ClientId: userPoolClientId,
				Username: email,
				ConfirmationCode: code,
			}),
		);
		this.logger.debug('result', result);

		return res.json({ message: 'User verified' });
	}

	// change password
	@Post('/changePassword', {
		validations: {
			accessToken: { required: true },
			oldPassword: { required: true },
			newPassword: { required: true }
		}
	})
	async changePassword(req: Request, res: Response) {
		const {accessToken, oldPassword, newPassword} = req.body as { accessToken: string; oldPassword: string; newPassword: string };

		const result = await identityProviderClient.send(
			new ChangePasswordCommand({
				AccessToken: accessToken,
				PreviousPassword: oldPassword,
				ProposedPassword: newPassword,
			}),
		);

		this.logger.debug('newPasswordResult', result);

		return res.json({ message: 'Password changed' });
	}

	// forgot password route
	@Post('/forgotPassword', {
		validations: {
			email: { required: true, datatype: 'email' },
		}
	})
	async forgotPassword(req: Request, res: Response) {
		const {email} = req.body as { email: string };

		const result = await identityProviderClient.send(
			new ForgotPasswordCommand({
				ClientId: this.getUserPoolClientId(),
				Username: email,
			}),
		);

		this.logger.debug('result', result);

		return res.json({ message: 'Password reset email sent' });
	}
	
	// confirm forgot password
	@Post('/confirmForgotPassword', {
		validations: {
			code: { required: true },
			email: { required: true, datatype: 'email' },
			newPassword: { required: true },
		}
	})
	async confirmForgotPassword(req: Request, res: Response) {
		const {email, code, newPassword} = req.body as { email: string; code: string; newPassword: string };

		const result = await identityProviderClient.send(
			new ConfirmForgotPasswordCommand({
				ClientId: this.getUserPoolClientId(),
				Username: email,
				ConfirmationCode: code,
				Password: newPassword,
			}),
		);

		this.logger.debug('result', result);

		return res.json({ message: 'Password reset'});
	}
	
	// Add user to group
	@Authorizer({type: 'AWS_IAM', requireRouteInGroupConfig: true})
	@Post('/addUserToGroup', {
		validations: {
			email: { required: true, datatype: 'email' },
			groupName: { required: true },
		}
	})
	async addUserToGroup(req: Request, res: Response) {
		const {email, groupName} = req.body as { email: string; groupName: string };

		const result = await identityProviderClient.send(
			new AdminAddUserToGroupCommand({
				UserPoolId: this.getUserPoolID(),
				GroupName: groupName,
				Username: email,
			}),
		);

		this.logger.debug('result', result);

		return res.json({ message: 'User added to group'});
	}

	// generate IAM Credentials from token
	@Post('/getCredentials', {
		validations: {
			idToken: { required: true },
		}
	})
	async getCredentials(req: Request, res: Response) {
		const {idToken} = req.body as { idToken: string};

		// validate the token
		const jwtVerifier = CognitoJwtVerifier.create({
			userPoolId: this.getUserPoolID(),
			clientId: this.getUserPoolClientId(),
			tokenUse: null,
		});

		try{
			const payload = await jwtVerifier.verify(idToken);
			this.logger.debug("Token is valid. Payload:", payload);
		} catch {
			this.logger.debug("Token not valid!");
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
		const identityResponse = await identityClient.send(identityCommand);
		const identityID = identityResponse.IdentityId;

		const credentialInput = {
			IdentityId: identityID,
			Logins: { 
				[providerName]: idToken,
			}
		};

		const command = new GetCredentialsForIdentityCommand(credentialInput);
		const credentialsResponse = await identityClient.send(command);

		return res.json(credentialsResponse);
	}
	
	// private function to get identity pool id
	private getIdentityPoolId() {
		return process.env['identityPoolID'] || '';
	}

	// private function to get userpool client id
	private getUserPoolClientId() {
		return process.env['userPoolClientID'] || '';
	}

	// private function to get userpool client id
	private getUserPoolID() {
		return process.env['userPoolID'] || '';
	}

}

export const handler: any = AuthController.CreateHandler(AuthController);
