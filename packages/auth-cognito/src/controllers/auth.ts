import { AuthModule } from './../index';
import { Controller, APIController, Request, Response, Post, Authorizer, InputValidationRule, Inject } from '@ten24group/fw24';

import { IAuthService } from '../interfaces';
import { AuthServiceDIToken } from '../const';

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
    authorizer: [ {
        name: 'authmodule', type: 'NONE'
    } ],
    env: [
        { name: 'userPoolId', prefix: 'UserPool_AuthModule' }, // 	USERPOOL_AUTHMODULE_USERPOOLID
        { name: 'identityPoolId', prefix: 'IdentityPool_AuthModule' },
        { name: 'userPoolClientId', prefix: 'UserPoolClient_AuthModule' },
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

    @Post('/signup', { validations: emailAndPasswordValidations })
    async signup(req: Request, res: Response) {
        const { email, password, autoSignIn = false } = req.body as EmailAndPassword & { autoSignIn?: boolean };

        await this.authService.signup(email, password);

        if (autoSignIn) {
            return await this.signin(req, res);
        }

        return res.json({
            message: 'User Signed Up'
        });
    }

    @Post('/signin', { validations: emailAndPasswordValidations })
    async signin(req: Request, res: Response) {
        const { email, password } = req.body as EmailAndPassword;

        const authResult = await this.authService.signin(email, password);

        // if the login attempt returned a challenge let the client know
        if ('challengeName' in authResult) {
            return res.json(authResult);
        }

        if (!authResult?.IdToken) {

            let response: any = {
                message: 'Authentication failed'
            };

            if (req.debugMode) {
                response = { ...response, ...authResult }
            }

            return res.status(401).json(response);
        }

        return res.json(authResult);
    }

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

    @Post('/forgotPassword', {
        validations: {
            email: { required: true, datatype: 'email' },
        }
    })
    async forgotPassword(req: Request, res: Response) {
        const { email } = req.body as { email: string };

        await this.authService.forgotPassword(email);

        return res.json({ message: 'Password reset email sent' });
    }

    @Post('/confirmForgotPassword', {
        validations: {
            code: { required: true },
            email: { required: true, datatype: 'email' },
            newPassword: { required: true },
        }
    })
    async confirmForgotPassword(req: Request, res: Response) {
        const { email, code, newPassword } = req.body as { email: string; code: string; newPassword: string };

        await this.authService.confirmForgotPassword(email, code, newPassword);

        return res.json({ message: 'Password reset' });
    }

    @Authorizer({ type: 'AWS_IAM', requireRouteInGroupConfig: true })
    @Post('/addUserToGroup', {
        validations: {
            email: { required: true, datatype: 'email' },
            groupName: { required: true },
        }
    })
    async addUserToGroup(req: Request, res: Response) {
        const { email, groupName } = req.body as { email: string; groupName: string };

        await this.authService.addUserToGroup(email, groupName);

        return res.json({ message: 'User added to group' });
    }

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
}
