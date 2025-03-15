import { AuthModule } from './../index';
import { Controller, APIController, Request, Response, Post, Authorizer, InputValidationRule, Inject } from '@ten24group/fw24';

import { IAuthService, UserMfaPreferenceOptions, AdminMfaSettings, SignUpOptions, SocialProvider } from '../interfaces';
import { AuthServiceDIToken } from '../const';

type SignUpRequest = {
    username?: string;
    password: string;
    email?: string;
    autoSignIn?: boolean;
    [key: string]: any;  // Allow arbitrary attributes
}

type SignInRequest = {
	username?: string;
	password: string;
	email?: string;
}

const signUpValidations: InputValidationRule<SignUpRequest> = {
    password: {
        required: true,
        /*
            minLength: 8,
            maxLength: 20,
            pattern: {
                validator: (inputVal: any) => Promise.resolve(customPasswordValidator(inputVal)),
            }
        */
    },
    // email: {
    //     datatype: 'email',  // But if provided, must be valid email
    // }
} as const;

const signInValidations: InputValidationRule<SignInRequest> = {
    // username: {
    //     required: true,
    // },
    password: {
        required: true,
    }
} as const;

@Controller('mauth', {
    authorizer: [ {
        name: 'authmodule', type: 'NONE'
    } ],
    env: [
        { name: 'userPoolID', prefix: 'userpool_authmodule' },
        { name: 'userPoolClientID', prefix: 'userpoolclient_authmodule' },
        { name: 'identityPoolID', prefix: 'identitypool_authmodule' },
        { name: 'authDomain', prefix: 'userpool_authmodule' },
        { name: 'supportedIdentityProviders', prefix: 'userpool_authmodule' },
    ],
    module: {
        providedBy: AuthModule
    }
})
export class AuthController extends APIController {

    constructor(
        @Inject(AuthServiceDIToken) private readonly authService: IAuthService
    ) {
        super();
    }

    async initialize() {
        return Promise.resolve();
    }

    /**
     * Sign up a new user with either username or email
     * 
     * Example request with both:
     * ```json
     * {
     *   "username": "johndoe",
     *   "email": "user@example.com",
     *   "password": "MySecurePassword123!"
     * }
     * ```
     * 
     * Example request with just email:
     * ```json
     * {
     *   "email": "user@example.com",
     *   "password": "MySecurePassword123!"
     * }
     * ```
     * 
     * Example request with just username:
     * ```json
     * {
     *   "username": "johndoe",
     *   "password": "MySecurePassword123!"
     * }
     * ```
     * 
     * Success response:
     * ```json
     * {
     *   "message": "User Signed Up"
     * }
     * ```
     * 
     * Error response when neither username nor email is provided:
     * ```json
     * {
     *   "message": "Either username or email must be provided"
     * }
     * ```
     * 
     * Note: If email is provided, the user will receive a verification code via email
     */
    @Post('/signup', { validations: signUpValidations })
    async signup(req: Request, res: Response) {
        try {
            const { username, password, email, autoSignIn = false, ...customAttributes } = req.body as SignUpRequest;

            if (!username && !email) {
                return res.status(400).json({
                    message: 'Either username or email must be provided'
                });
            }

            const signupUsername = username || email;

            // Pass all attributes directly to the signup method
            const result = await this.authService.signup({
                username: signupUsername as string,  // We know it's not undefined due to the check above
                password,
                email,
                autoSignIn,
                ...customAttributes
            });

            return res.json(result);
        } catch (error: any) {
            return res.status(400).json({
                message: error.message
            });
        }
    }

    /**
     * Get available login options for a user
     * Used to determine what authentication methods are available
     * 
     * Example request:
     * ```json
     * {
     *   "username": "user@example.com"
     * }
     * ```
     * 
     * Example response:
     * ```json
     * {
     *   "challenges": ["EMAIL_OTP", "PASSWORD"],
     *   "session": "session-token-string"
     * }
     * ```
     */
    @Post('/getLoginOptions', {
        validations: {
            username: { required: true }
        }
    })
    async getLoginOptions(req: Request, res: Response) {
        const { username } = req.body as { username: string };

        const loginOptions = await this.authService.getLoginOptions(username);

        return res.json(loginOptions);
    }

    /**
     * Initiate OTP authentication flow
     * This endpoint starts the OTP challenge by requesting a code to be sent
     * 
     * Example request:
     * ```json
     * {
     *   "username": "user@example.com",
     *   "session": "session-token-from-getLoginOptions"
     * }
     * ```
     * 
     * Example response:
     * ```json
     * {
     *   "session": "new-session-token",
     *   "challengeName": "EMAIL_OTP",
     *   "challengeParameters": {
     *     "CODE_DELIVERY_DESTINATION": "m***@e***.com"
     *   }
     * }
     * ```
     */
    @Post('/initiateOtpAuth', {
        validations: {
            username: { required: true },
            session: { required: true }
        }
    })
    async initiateOtpAuth(req: Request, res: Response) {
        const { username, session } = req.body as { username: string; session: string };

        const result = await this.authService.initiateOtpAuth(username, session);

        return res.json(result);
    }

    /**
     * Complete OTP authentication by submitting the received code
     * 
     * Example request:
     * ```json
     * {
     *   "username": "user@example.com",
     *   "session": "session-token-from-initiateOtpAuth",
     *   "code": "123456"
     * }
     * ```
     * 
     * Success response (tokens issued):
     * ```json
     * {
     *   "AccessToken": "access-token",
     *   "IdToken": "id-token",
     *   "RefreshToken": "refresh-token",
     *   "TokenType": "Bearer",
     *   "ExpiresIn": 3600
     * }
     * ```
     * 
     * Challenge response (if additional steps needed):
     * ```json
     * {
     *   "session": "new-session-token",
     *   "challengeName": "NEXT_CHALLENGE_NAME",
     *   "challengeParameters": {}
     * }
     * ```
     */
    @Post('/respondToOtpChallenge', {
        validations: {
            username: { required: true },
            session: { required: true },
            code: { required: true }
        }
    })
    async respondToOtpChallenge(req: Request, res: Response) {
        const { username, session, code } = req.body as { username: string; session: string; code: string };

        const result = await this.authService.respondToOtpChallenge(username, session, code);

        return res.json(result);
    }

    /**
     * Sign in with email and password
     * 
     * Example request with username and password:
     * ```json
     * {
     *   "username": "johndoe",
     *   "password": "MySecurePassword123!"
     * }
     * ```
     * 
     * Example request with just email:
     * ```json
     * {
     *   "email": "user@example.com",
     *   "password": "MySecurePassword123!"
     * 
     * Success response (tokens issued):
     * ```json
     * {
     *   "AccessToken": "access-token",
     *   "IdToken": "id-token",
     *   "RefreshToken": "refresh-token",
     *   "TokenType": "Bearer",
     *   "ExpiresIn": 3600
     * }
     * ```
     * 
     * Challenge response (if MFA or other challenge required):
     * ```json
     * {
     *   "challengeName": "SMS_MFA",
     *   "session": "session-token",
     *   "challengeParameters": {
     *     "CODE_DELIVERY_DESTINATION": "+1********99"
     *   }
     * }
     * ```
     */
    @Post('/signin', { validations: signInValidations })
    async signin(req: Request, res: Response) {
        const { username, password, email } = req.body as SignInRequest;

        if(!username && !email){
            return res.status(400).json({
                message: 'Either username or email must be provided'
            });
        }

        const signinUsername = username || email;

        const result = await this.authService.signin(signinUsername!, password);

        // if the login attempt returned a challenge let the client know
        if('challengeName' in result){
            return res.json( result );
        }

        const idToken = result?.IdToken;
        if (idToken === undefined) {
            
            let response: any = {
                message: 'Authentication failed'
            };
            
            if(req.debugMode){
                response = {...response, result}
            }

            return res.status(401).json(response);
        }

        return res.json(result);
    }

    /**
     * Sign out a user by invalidating their access token
     * 
     * Example request:
     * ```json
     * {
     *   "accessToken": "user-access-token"
     * }
     * ```
     * 
     * Success response:
     * ```json
     * {
     *   "message": "User logged out"
     * }
     * ```
     */
    @Post('/signout', {
        validations: { accessToken: { required: true } }
    })
    async signout(req: Request, res: Response) {
        const { accessToken } = req.body as { accessToken: string };

        await this.authService.signout(accessToken);

        return res.json({
            message: 'User logged out'
        });
    }

    /**
     * Refresh access and ID tokens using a refresh token
     * 
     * Example request:
     * ```json
     * {
     *   "refreshToken": "your-refresh-token"
     * }
     * ```
     * 
     * Success response:
     * ```json
     * {
     *   "AccessToken": "new-access-token",
     *   "IdToken": "new-id-token",
     *   "RefreshToken": "same-refresh-token",
     *   "TokenType": "Bearer",
     *   "ExpiresIn": 3600
     * }
     * ```
     * 
     * Note: The refresh token remains the same as Cognito does not issue new refresh tokens during refresh.
     * Refresh tokens are valid for 30 days by default.
     */
    @Post('/refreshToken', {
        validations: {
            refreshToken: { required: true }
        }
    })
    async refreshToken(req: Request, res: Response) {
        const { refreshToken } = req.body as { refreshToken: string };

        const result = await this.authService.refreshToken(refreshToken);

        return res.json(result);
    }

    /**
     * Verify a user's email with the code they received
     * 
     * Example request:
     * ```json
     * {
     *   "email": "user@example.com",
     *   "code": "123456"
     * }
     * ```
     * 
     * Success response:
     * ```json
     * {
     *   "message": "User verified"
     * }
     * ```
     */
    @Post('/verify', {
        validations: {
            code: { required: true },
            email: { required: true, datatype: 'email' },
        }
    })
    async verify(req: Request, res: Response) {
        const { email, code } = req.body as { email: string; code: string };

        await this.authService.verify(email, code);

        return res.json({ message: 'User verified' });
    }

    /**
     * Get verification code for a user attribute (e.g., email)
     * This will send a verification code to the specified attribute
     * 
     * Example request:
     * ```json
     * {
     *   "accessToken": "user-access-token",
     *   "attributeName": "email"
     * }
     * ```
     * 
     * Success response:
     * ```json
     * {
     *   "message": "Verification code sent"
     * }
     * ```
     */
    @Post('/getUserAttributeVerificationCode', {
        validations: {
            accessToken: { required: true },
            attributeName: { required: true },
        }
    })
    async getUserAttributeVerificationCode(req: Request, res: Response) {
        const { accessToken, attributeName } = req.body as { 
            accessToken: string;
            attributeName: string;
        };

        await this.authService.getUserAttributeVerificationCode(accessToken, attributeName);

        return res.json({ message: 'Verification code sent' });
    }

    /**
     * Verify a user attribute (e.g., email) with a verification code
     * First call /getUserAttributeVerificationCode to get the code, then use this endpoint to verify
     * 
     * Example request:
     * ```json
     * {
     *   "accessToken": "user-access-token",
     *   "attributeName": "email",
     *   "code": "123456"
     * }
     * ```
     * 
     * Success response:
     * ```json
     * {
     *   "message": "Attribute verified"
     * }
     * ```
     */
    @Post('/verifyUserAttribute', {
        validations: {
            accessToken: { required: true },
            attributeName: { required: true },
            code: { required: true },
        }
    })
    async verifyUserAttribute(req: Request, res: Response) {
        const { accessToken, attributeName, code } = req.body as { 
            accessToken: string;
            attributeName: string;
            code: string;
        };

        await this.authService.verifyUserAttribute(accessToken, attributeName, code);

        return res.json({ message: 'Attribute verified' });
    }

    /**
     * Resend verification code to a user's email
     * 
     * Example request with email:
     * ```json
     * {
     *   "email": "user@example.com"
     * }
     * ```
     * 
     * Example request with username:
     * ```json
     * {
     *   "username": "johndoe"
     * }
     * ```
     * 
     * Success response:
     * ```json
     * {
     *   "message": "Verification code resent"
     * }
     * ```
     */
    @Post('/resendVerificationCode')
    async resendVerificationCode(req: Request, res: Response) {
        const { email, username } = req.body as { email?: string; username?: string };

        if (!email && !username) {
            return res.status(400).json({
                message: 'Either email or username must be provided'
            });
        }

        const verificationUsername = username || email;
        await this.authService.resendVerificationCode(verificationUsername!);

        return res.json({ message: 'Verification code resent' });
    }

    /**
     * Change a user's password
     * Requires the user to be authenticated with a valid access token
     * 
     * Example request:
     * ```json
     * {
     *   "accessToken": "user-access-token",
     *   "oldPassword": "OldPassword123!",
     *   "newPassword": "NewPassword456!"
     * }
     * ```
     * 
     * Success response:
     * ```json
     * {
     *   "message": "Password changed"
     * }
     * ```
     */
    @Post('/changePassword', {
        validations: {
            accessToken: { required: true },
            oldPassword: { required: true },
            newPassword: { required: true }
        }
    })
    async changePassword(req: Request, res: Response) {
        const { accessToken, oldPassword, newPassword } = req.body as { accessToken: string; oldPassword: string; newPassword: string };

        await this.authService.changePassword(accessToken, oldPassword, newPassword);

        return res.json({ message: 'Password changed' });
    }

    /**
     * Initiate the forgot password flow
     * This will send a reset code to the user's email
     * 
     * Example request:
     * ```json
     * {
     *   "email": "user@example.com"
     * }
     * ```
     * 
     * Success response:
     * ```json
     * {
     *   "message": "Password reset email sent"
     * }
     * ```
     */
    @Post('/forgotPassword', {
        // validations: {
        //     email: { required: true, datatype: 'email' },
        // }
    })
    async forgotPassword(req: Request, res: Response) {
        const { email, username } = req.body as { email?: string, username?: string };

        if(!email && !username){
            return res.status(400).json({
                message: 'Either email or username must be provided'
            });
        }

        const forgotPasswordUsername = username || email;

        await this.authService.forgotPassword(forgotPasswordUsername!);

        return res.json({ message: 'Password reset email sent' });
    }

    /**
     * Complete the forgot password flow by setting a new password with the reset code
     * 
     * Example request:
     * ```json
     * {
     *   "email": "user@example.com",
     *   "code": "123456",
     *   "newPassword": "NewPassword456!"
     * }
     * ```
     * 
     * Success response:
     * ```json
     * {
     *   "message": "Password reset"
     * }
     * ```
     */
    @Post('/confirmForgotPassword', {
        validations: {
            code: { required: true },
            // email: { required: true, datatype: 'email' },
            newPassword: { required: true },
        }
    })
    async confirmForgotPassword(req: Request, res: Response) {
        const { email, username, code, newPassword } = req.body as { email?: string, username?: string, code: string, newPassword: string };

        if(!email && !username){
            return res.status(400).json({
                message: 'Either email or username must be provided'
            });
        }

        const confirmForgotPasswordUsername = username || email;

        await this.authService.confirmForgotPassword(confirmForgotPasswordUsername!, code, newPassword);

        return res.json({ message: 'Password reset' });
    }

    /**
     * Admin endpoint to add a user to a group
     * Requires AWS IAM authorization and appropriate group permissions
     * 
     * Example request:
     * ```json
     * {
     *   "email": "user@example.com",
     *   "groupName": "admin"
     * }
     * ```
     * 
     * Success response:
     * ```json
     * {
     *   "message": "User added to group"
     * }
     * ```
     * 
     * Note: This endpoint requires the route to be included in the admin group configuration
     * and proper AWS IAM authorization.
     */
    @Authorizer({ type: 'AWS_IAM', requireRouteInGroupConfig: true })
    @Post('/addUserToGroup', {
        validations: {
            // email: { required: true, datatype: 'email' },
            groupName: { required: true },
        }
    })
    async addUserToGroup(req: Request, res: Response) {
        const { email, username, groupName } = req.body as { email?: string, username?: string, groupName: string };

        if(!email && !username){
            return res.status(400).json({
                message: 'Either email or username must be provided'
            });
        }

        const addUserToGroupUsername = username || email;

        await this.authService.addUserToGroup(addUserToGroupUsername!, groupName);

        return res.json({ message: 'User added to group' });
    }

    /**
     * Get AWS credentials using an ID token
     * Used for AWS IAM authentication
     * 
     * Example request:
     * ```json
     * {
     *   "idToken": "cognito-id-token"
     * }
     * ```
     * 
     * Success response:
     * ```json
     * {
     *   "Credentials": {
     *     "AccessKeyId": "ASIA...",
     *     "SecretKey": "...",
     *     "SessionToken": "...",
     *     "Expiration": "2024-03-21T00:00:00.000Z"
     *   },
     *   "IdentityId": "us-east-1:..."
     * }
     * ```
     */
    @Post('/getCredentials', {
        validations: {
            idToken: { required: true },
        }
    })
    async getCredentials(req: Request, res: Response) {
        const { idToken } = req.body as { idToken: string };

        const credentials = await this.authService.getCredentials(idToken);

        return res.json(credentials);
    }

    /**
     * Update MFA preferences for the authenticated user
     * 
     * Example request:
     * ```json
     * {
     *   "accessToken": "user-access-token",
     *   "mfaPreference": {
     *     "enabledMethods": ["EMAIL", "SMS"],  // Available methods: "EMAIL", "SMS", "SOFTWARE_TOKEN"
     *     "preferredMethod": "EMAIL"
     *   }
     * }
     * ```
     * 
     * Common use cases:
     * 1. Enable email MFA only:
     * ```json
     * {
     *   "accessToken": "user-access-token",
     *   "mfaPreference": {
     *     "enabledMethods": ["EMAIL"],
     *     "preferredMethod": "EMAIL"
     *   }
     * }
     * ```
     * 
     * 2. Enable multiple methods with SMS preferred:
     * ```json
     * {
     *   "accessToken": "user-access-token",
     *   "mfaPreference": {
     *     "enabledMethods": ["EMAIL", "SMS", "SOFTWARE_TOKEN"],
     *     "preferredMethod": "SMS"
     *   }
     * }
     * ```
     * 
     * 3. Disable all MFA:
     * ```json
     * {
     *   "accessToken": "user-access-token",
     *   "mfaPreference": {
     *     "enabledMethods": []
     *   }
     * }
     * ```
     */
    @Post('/updateUserMfaPreference', {
        validations: {
            accessToken: { required: true },
            mfaPreference: { required: true },
        }
    })
    async updateUserMfaPreference(req: Request, res: Response) {    
        const { accessToken, mfaPreference } = req.body as { accessToken: string; mfaPreference: UserMfaPreferenceOptions };

        await this.authService.updateUserMfaPreference(accessToken, mfaPreference);

        return res.json({ message: 'User MFA preference updated' });
    }

    /**
     * Admin endpoint to manage MFA settings for any user
     * Requires AWS IAM authorization and appropriate group permissions
     * 
     * Example request:
     * ```json
     * {
     *   "username": "user@example.com",
     *   "enabledMethods": ["EMAIL", "SMS"],  // Available methods: "EMAIL", "SMS", "SOFTWARE_TOKEN"
     *   "preferredMethod": "EMAIL"
     * }
     * ```
     * 
     * Common use cases:
     * 1. Force enable email MFA for a user:
     * ```json
     * {
     *   "username": "user@example.com",
     *   "enabledMethods": ["EMAIL"],
     *   "preferredMethod": "EMAIL"
     * }
     * ```
     * 
     * 2. Enable multiple methods for a user:
     * ```json
     * {
     *   "username": "user@example.com",
     *   "enabledMethods": ["EMAIL", "SMS"],
     *   "preferredMethod": "SMS"
     * }
     * ```
     * 
     * 3. Disable all MFA for a user:
     * ```json
     * {
     *   "username": "user@example.com",
     *   "enabledMethods": []
     * }
     * ```
     * 
     * Note: This endpoint requires the route to be included in the admin group configuration
     * and proper AWS IAM authorization.
     */
    @Authorizer({ type: 'AWS_IAM', requireRouteInGroupConfig: true })
    @Post('/setUserMfaSettings', {
        validations: {
            username: { required: true },
            enabledMethods: { required: true },
            preferredMethod: { required: false },
        }
    })
    async setUserMfaSettings(req: Request, res: Response) {    
        const { username, enabledMethods, preferredMethod } = req.body as AdminMfaSettings;

        await this.authService.setUserMfaSettings({ username, enabledMethods, preferredMethod });

        return res.json({ message: 'User MFA settings updated' });
    }

    /**
     * Get social sign-in configuration
     * This endpoint returns the configuration for all enabled social providers
     * 
     * Example request:
     * ```json
     * {
     *   "redirectUri": "http://localhost:3000/auth/callback"
     * }
     * ```
     * 
     * Success response:
     * ```json
     * {
     *   "Google": {
     *     "authorizationUrl": "https://your-cognito-domain.auth.region.amazoncognito.com/oauth2/authorize?...",
     *     "clientId": "your-client-id",
     *     "redirectUri": "http://localhost:3000/auth/callback",
     *     "grantType": "authorization_code"
     *   },
     *   "Facebook": {
     *     "authorizationUrl": "https://your-cognito-domain.auth.region.amazoncognito.com/oauth2/authorize?...",
     *     "clientId": "your-client-id",
     *     "redirectUri": "http://localhost:3000/auth/callback",
     *     "grantType": "authorization_code"
     *   }
     * }
     * ```
     */
    @Post('/getSocialSignInConfig', {
        validations: {
            redirectUri: { required: true }
        }
    })
    async getSocialSignInConfig(req: Request, res: Response) {
        const { redirectUri } = req.body as { redirectUri: string };

        const configs = await this.authService.getSocialSignInConfig(redirectUri);

        return res.json(configs);
    }

    /**
     * Initiate social sign-in flow
     * This endpoint returns the URL to redirect the user to for social login
     * 
     * Example request:
     * ```json
     * {
     *   "provider": "Google",
     *   "redirectUri": "http://localhost:3000/auth/callback"
     * }
     * ```
     * 
     * Success response:
     * ```json
     * {
     *   "authorizationUrl": "https://accounts.google.com/o/oauth2/v2/auth?..."
     * }
     * ```
     */
    @Post('/initiateSocialSignIn', {
        validations: {
            provider: { required: true },
            redirectUri: { required: true }
        }
    })
    async initiateSocialSignIn(req: Request, res: Response) {
        const { provider, redirectUri } = req.body as { provider: SocialProvider; redirectUri: string };

        const authUrl = await this.authService.initiateSocialSignIn(provider, redirectUri);

        return res.json({ authorizationUrl: authUrl });
    }

    /**
     * Complete social sign-in flow
     * This endpoint handles the OAuth callback and returns user tokens
     * 
     * Example request:
     * ```json
     * {
     *   "provider": "Google",
     *   "code": "authorization-code-from-callback",
     *   "redirectUri": "http://localhost:3000/auth/callback"
     * }
     * ```
     * 
     * Success response:
     * ```json
     * {
     *   "AccessToken": "access-token",
     *   "IdToken": "id-token",
     *   "RefreshToken": "refresh-token",
     *   "TokenType": "Bearer",
     *   "ExpiresIn": 3600,
     *   "isNewUser": false,
     *   "provider": "Google"
     * }
     * ```
     */
    @Post('/completeSocialSignIn', {
        validations: {
            provider: { required: true },
            code: { required: true },
            redirectUri: { required: true }
        }
    })
    async completeSocialSignIn(req: Request, res: Response) {
        const { provider, code, redirectUri } = req.body as { 
            provider: SocialProvider;
            code: string;
            redirectUri: string;
        };

        const result = await this.authService.completeSocialSignIn(provider, code, redirectUri);

        return res.json(result);
    }

    /**
     * Link social provider to existing account
     * This endpoint allows users to link their social accounts to their existing Cognito account
     * 
     * Example request:
     * ```json
     * {
     *   "accessToken": "user-access-token",
     *   "provider": "Google",
     *   "code": "authorization-code-from-oauth",
     *   "redirectUri": "http://localhost:3000/auth/callback"
     * }
     * ```
     * 
     * Success response:
     * ```json
     * {
     *   "message": "Social provider linked successfully",
     *   "provider": "Google"
     * }
     * ```
     */
    @Post('/linkSocialProvider', {
        validations: {
            accessToken: { required: true },
            provider: { required: true },
            code: { required: true },
            redirectUri: { required: true }
        }
    })
    async linkSocialProvider(req: Request, res: Response) {
        const { accessToken, provider, code, redirectUri } = req.body as {
            accessToken: string;
            provider: SocialProvider;
            code: string;
            redirectUri: string;
        };

        await this.authService.linkSocialProvider(accessToken, provider, code, redirectUri);

        return res.json({
            message: 'Social provider linked successfully',
            provider
        });
    }

    /**
     * Unlink social provider from account
     * This endpoint allows users to remove a linked social provider from their account
     * 
     * Example request:
     * ```json
     * {
     *   "accessToken": "user-access-token",
     *   "provider": "Google"
     * }
     * ```
     * 
     * Success response:
     * ```json
     * {
     *   "message": "Social provider unlinked successfully",
     *   "provider": "Google"
     * }
     * ```
     */
    @Post('/unlinkSocialProvider', {
        validations: {
            accessToken: { required: true },
            provider: { required: true }
        }
    })
    async unlinkSocialProvider(req: Request, res: Response) {
        const { accessToken, provider } = req.body as {
            accessToken: string;
            provider: SocialProvider;
        };

        await this.authService.unlinkSocialProvider(accessToken, provider);

        return res.json({
            message: 'Social provider unlinked successfully',
            provider
        });
    }

    /**
     * Complete the NEW_PASSWORD_REQUIRED challenge by setting a new password
     * 
     * Example request:
     * ```json
     * {
     *   "username": "user@example.com",
     *   "session": "session-token-from-login",
     *   "newPassword": "NewSecurePassword123!"
     * }
     * ```
     * 
     * Success response (tokens issued):
     * ```json
     * {
     *   "AccessToken": "access-token",
     *   "IdToken": "id-token",
     *   "RefreshToken": "refresh-token",
     *   "TokenType": "Bearer",
     *   "ExpiresIn": 3600
     * }
     * ```
     */
    @Post('/setNewPassword', {
        validations: {
            username: { required: true },
            session: { required: true },
            newPassword: { required: true }
        }
    })
    async setNewPassword(req: Request, res: Response) {
        const { username, session, newPassword } = req.body as { 
            username: string;
            session: string;
            newPassword: string;
        };

        try {
            const result = await this.authService.respondToNewPasswordChallenge(
                username,
                newPassword,
                session
            );

            return res.json(result);
        } catch (error: any) {
            return res.status(400).json({
                message: error.message || 'Failed to set new password'
            });
        }
    }
}
