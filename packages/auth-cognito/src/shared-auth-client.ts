import { Inject } from "@ten24group/fw24";
import { AuthServiceDIToken } from "./const";
import { IAuthService } from "./interfaces";

import { Auth } from "@ten24group/fw24-common";

export class SharedAuthClient implements Auth.IAuthModuleClient {
    
    constructor(
        @Inject(AuthServiceDIToken) private readonly authService: IAuthService
    ) {}

    public async createUserAuth(options: Auth.CreateUserAuthenticationOptions): Promise<void> {
      
        const { userId: _userId, email, password, groups = [] } = options;
        
        const _user = await this.authService.signup(email, password);

        // TODO: is user-ID needed [multiple emails for same user, multiple accounts with same email ?? ]

        await Promise.all( 
            groups.map(
                async group => await this.authService.addUserToGroup(options.email, group)
            )
        );
    }
}