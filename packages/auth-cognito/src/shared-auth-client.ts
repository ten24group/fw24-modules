import { createLogger, Inject } from "@ten24group/fw24";
import { AuthServiceDIToken } from "./const";
import { AddUserToGroupOptions, CreateUserAuthenticationOptions, IAuthModuleClient, IAuthService, RemoveUserFromGroupOptions, ResetUserPasswordOptions, SetUserGroupsOptions, SetUserPasswordOptions } from "./interfaces";

export class SharedAuthClient implements IAuthModuleClient {

    private readonly logger = createLogger(SharedAuthClient);
    
    constructor(
        @Inject(AuthServiceDIToken) private readonly authService: IAuthService
    ) {}

    async createUserAuth(options: CreateUserAuthenticationOptions): Promise<void> {
      
        const { username, password, groups = [] } = options;

        await this.authService.createUser({
            username,
            tempPassword: password,
            attributes: [{
                Name: 'email',
                Value: username,
            }]
        });

        await this.authService.updateUserAttributes({
            username,
            attributes: [{
                Name: 'email_verified',
                Value: 'true'
            }]
        })

        // this is required else user is stuck in the confirmed status, and we can't initiate the forgot-password flow
        await this.authService.setPassword(
            username,
            password,
            false
        )

        await this.authService.forgotPassword(username);

        await this.authService.setUserGroups(username, groups);
    }

    async addUserToGroup(options: AddUserToGroupOptions ): Promise<void> {
        await this.authService.addUserToGroup(options.username, options.group);
    }

    async setUserGroups(options: SetUserGroupsOptions ): Promise<void> {
        const { username, groups = [] } = options;

        await this.authService.setUserGroups(username, groups);
    }

    async removeUserFromGroup(options: RemoveUserFromGroupOptions): Promise<void> {
        await this.authService.removeUserFromGroup(options.username, options.group);
    }

    async setUserPassword(options: SetUserPasswordOptions): Promise<void>{
        return await this.authService.setPassword(options.username, options.password, options.forceChangePassword);
    };

    async resetUserPassword(options: ResetUserPasswordOptions): Promise<void>{
        return await this.authService.resetPassword(options.username);
    };

}