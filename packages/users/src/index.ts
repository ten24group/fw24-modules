import { AbstractFw24Module, FW24Construct, createLogger, ILogger, DIModule, DIContainer } from '@ten24group/fw24';
import { UserSchemaDIToken } from './const';
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

    getName(): string {
        return 'UsersModule';
    }

    getBasePath(): string {
        return __dirname;
    }

    getConstructs(): Map<string, FW24Construct> {
        return new Map<string, FW24Construct>();
    }

    getQueuesDirectory(): string {
        return '';
    }

    getQueueFileNames(): string[] {
        return [];
    }

    getTasksDirectory(): string {
        return '';
    }

    getTaskFileNames(): string[] {
        return [];
    }

    getDependencies(): string[] {
        return [];
    }
}