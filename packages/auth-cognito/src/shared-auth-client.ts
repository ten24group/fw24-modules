import { Inject } from "@ten24group/fw24";
import { AuthServiceDIToken } from "./const";
import { AddUserToGroupOptions, CreateUserAuthenticationOptions, IAuthModuleClient, IAuthService, SetUserGroupsOptions } from "./interfaces";

export class SharedAuthClient implements IAuthModuleClient {
    
    constructor(
        @Inject(AuthServiceDIToken) private readonly authService: IAuthService
    ) {}

    public async createUserAuth(options: CreateUserAuthenticationOptions): Promise<void> {
      
        const { userId: _userId, email, password, groups = [] } = options;
        
        const _user = await this.authService.signup(email, password);

        // TODO: is user-ID needed [multiple emails for same user, multiple accounts with same email ?? ]

        await this.setUserGroups({email: options.email, groups: options.groups})
    }

    public async addUserToGroup(options: AddUserToGroupOptions ){
        await this.authService.addUserToGroup(options.email, options.group);
    }

    public async setUserGroups(options: SetUserGroupsOptions ){
        
        options.groups = options.groups || [];

        await Promise.all( 
            options.groups.map(
                async group => await this.addUserToGroup({email: options.email, group})
            )
        );
    }
}