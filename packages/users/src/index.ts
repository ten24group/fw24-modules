import { AbstractFw24Module, FW24Construct, createLogger, ILogger, DIModule } from '@ten24group/fw24';
import { NEW_USER_GROUPS_KEY, TABLE_NAME_KEY, ADMIN_USER_GROUPS_KEY } from './const';
import { createUserSchema } from './entities/user';
import { IUsersModuleConfig } from './interfaces';
import { UserService } from './services/user';

@DIModule({
    providers: [
        {
            type: 'schema', 
            forEntity: 'user',
            provide: 'userSchema',
            useFactory: createUserSchema,
        },
        {
            type: 'service',
            forEntity: 'user',
            provide: UserService,
            useClass: UserService,
        }
    ],
    exports: ['userSchema', UserService]
})
export class UsersModule extends AbstractFw24Module {
    readonly logger: ILogger = createLogger(UsersModule);

    constructor( protected readonly config: IUsersModuleConfig, ){
        super(config);
    }

    getBasePath(): string {
        return __dirname;
    }

    getConstructs(): Map<string, FW24Construct> {
        return new Map<string, FW24Construct>();
    }

    getExportedEnvironmentVariables(): Map<string, string> {
        const envVars = new Map<string, string>();
        envVars.set(TABLE_NAME_KEY, this.config.tableName);
        envVars.set(NEW_USER_GROUPS_KEY, Array.isArray(this.config.userGroups) ? this.config.userGroups.join(',') : this.config.userGroups);
        envVars.set(ADMIN_USER_GROUPS_KEY, Array.isArray(this.config.adminUserGroups) ? this.config.adminUserGroups.join(',') : this.config.adminUserGroups);
        return envVars;
    }
}