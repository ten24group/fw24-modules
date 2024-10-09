import { Inject } from "@ten24group/fw24";
import { AuthServiceDIToken } from "./const";
import { AddUserToGroupOptions, CreateUserAuthenticationOptions, IAuthModuleClient, IAuthService, SetUserGroupsOptions } from "./interfaces";

export class SharedAuthClient implements IAuthModuleClient {
    
    constructor(
        @Inject(AuthServiceDIToken) private readonly authService: IAuthService
    ) {}

    async createUserAuth(options: CreateUserAuthenticationOptions): Promise<void> {
      
        const { username, password, groups = [] } = options;
        
        await this.authService.signup(username, password);

        await this.authService.setUserGroups(username, groups);
    }

    async addUserToGroup(options: AddUserToGroupOptions ): Promise<void> {
        await this.authService.addUserToGroup(options.username, options.group);
    }

    async setUserGroups(options: SetUserGroupsOptions ): Promise<void> {
        const { username, groups = [] } = options;

        await this.authService.setUserGroups(username, groups);
    }

    async removeUserFromGroup(username: string, groupName: string): Promise<void> {
        await this.authService.removeUserFromGroup(username, groupName);
    }
}