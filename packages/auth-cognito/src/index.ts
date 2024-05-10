import { AbstractFw24Module, FW24Construct, AuthConstruct, IAuthConstructConfig, createLogger, LambdaFunctionProps, ILogger } from '@ten24group/fw24';
import { join } from 'path';

export interface IAuthModuleConfig extends IAuthConstructConfig {
    
}

export class AuthModule extends AbstractFw24Module {
    readonly logger: ILogger = createLogger(AuthConstruct.name);

    protected constructs: Map<string, FW24Construct>; 

    // array of type of stacks that this stack is dependent on
    dependencies: string[] = [];

    constructor( protected readonly config: IAuthModuleConfig){
        super(config);
        this.constructs = new Map();

        if(config.groups){
            const autoUserSignupHandler: LambdaFunctionProps = {
                entry: join(__dirname,'functions/auto-post-confirmation.js')
            }
            config.groups.filter(group => group.autoUserSignup).map(group => Object.assign(group, {autoUserSignupHandler: autoUserSignupHandler}));
        }
        this.logger.debug("AuthModule: ", config);
        const cognito = new AuthConstruct({	
            name: 'authmodule',
            ...config,
        });

        this.constructs.set('auth-cognito', cognito );

    }

    getName(): string {
        return 'AuthModule';
    }

    getBasePath(): string {
        return __dirname;
    }

    getConstructs(): Map<string, FW24Construct> {
        return this.constructs;
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
        return this.dependencies;
    }
}