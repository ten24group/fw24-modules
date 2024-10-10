import { AbstractFw24Module, FW24Construct, createLogger, ILogger, DIModule } from '@ten24group/fw24';
import { NEW_USER_GROUPS, TABLE_NAME, APIS_AUTH_GROUPS, UserSchemaDIToken } from './const';
import { createUserSchema } from './entities/user';
import { IUsersModuleConfig } from './interfaces';

@DIModule({
    providers: [{
        provide: UserSchemaDIToken,
        useFactory: createUserSchema
    }],
    exports: [UserSchemaDIToken]
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
        envVars.set(TABLE_NAME, this.config.tableName);
        envVars.set(NEW_USER_GROUPS, Array.isArray(this.config.userGroups) ? this.config.userGroups.join(',') : this.config.userGroups);
        envVars.set(APIS_AUTH_GROUPS, Array.isArray(this.config.apiAuthGroups) ? this.config.apiAuthGroups.join(',') : this.config.apiAuthGroups);
        return envVars;
    }
}