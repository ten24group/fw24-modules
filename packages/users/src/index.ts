import { AbstractFw24Module, FW24Construct, createLogger, ILogger, DIModule } from '@ten24group/fw24';
import { USER_MODULE_TABLE_NAME, UserSchemaDIToken } from './const';
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
        envVars.set(USER_MODULE_TABLE_NAME, this.config.tableName);
        return envVars;
    }
}