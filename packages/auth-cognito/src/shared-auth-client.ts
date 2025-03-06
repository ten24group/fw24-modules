import { createLogger, Inject } from "@ten24group/fw24";
import { AuthServiceDIToken } from "./const";
import { AddUserToGroupOptions, CreateUserAuthenticationOptions, CreateUserOptions, IAuthModuleClient, IAuthService, RemoveUserFromGroupOptions, ResetUserPasswordOptions, SetUserGroupsOptions, SetUserPasswordOptions, SignInResult, UserDetails } from "./interfaces";

export class SharedAuthClient implements IAuthModuleClient {

    private readonly logger = createLogger(SharedAuthClient);

    constructor(
        @Inject(AuthServiceDIToken) private readonly authService: IAuthService
    ) { }

    async getUser(usernameOrEmail: string): Promise<UserDetails> {
        return this.authService.getUser(usernameOrEmail)
    }

    async createUserAuth(options: CreateUserAuthenticationOptions): Promise<void | SignInResult> {

        const { username, password, groups = [], userAttributes = [], autoLogin, autoTriggerForgotPassword, autoVerifyEmail } = options;

        const emailAttributeExists = userAttributes.find(att => att.Name === 'email');

        if (!emailAttributeExists) {
            userAttributes.push({
                Name: 'email',
                Value: username,
            })
        }

        await this.authService.createUser({
            username,
            tempPassword: password,
            attributes: userAttributes
        });

        // verify the user so they can proceed with login
        if (autoVerifyEmail) {
            await this.authService.updateUserAttributes({
                username,
                attributes: [ {
                    Name: 'email_verified',
                    Value: 'true'
                } ]
            })
        }

        // trigger forgot-password flow, so the user will get an email to reset the password
        if (autoTriggerForgotPassword) {
            // this is required else user is stuck in the confirmed status, and we can't initiate the forgot-password flow
            await this.authService.setPassword(
                username,
                password,
                false
            )

            await this.authService.forgotPassword(username);
        }

        // add user groups
        await this.authService.setUserGroups(username, groups);

        // login
        if (autoLogin) {
            const result = await this.authService.signin(username, password);

            return result;
        }
    }

    async createUser(options: CreateUserOptions): Promise<void> {
        await this.authService.createUser(options);
    }

    async addUserToGroup(options: AddUserToGroupOptions): Promise<void> {
        await this.authService.addUserToGroup(options.username, options.group);
    }

    async setUserGroups(options: SetUserGroupsOptions): Promise<void> {
        const { username, groups = [] } = options;

        await this.authService.setUserGroups(username, groups);
    }

    async removeUserFromGroup(options: RemoveUserFromGroupOptions): Promise<void> {
        await this.authService.removeUserFromGroup(options.username, options.group);
    }

    async setUserPassword(options: SetUserPasswordOptions): Promise<void> {
        return await this.authService.setPassword(options.username, options.password, options.forceChangePassword);
    };

    async resetUserPassword(options: ResetUserPasswordOptions): Promise<void> {
        return await this.authService.resetPassword(options.username);
    };

}