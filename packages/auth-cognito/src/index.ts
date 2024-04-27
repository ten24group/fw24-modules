import { AbstractFw24Module, IStack, CognitoStack, ICognitoConfig, createLogger, LambdaFunctionProps, ILogger } from '@ten24group/fw24';
import { join } from 'path';

export interface IAuthModuleConfig extends ICognitoConfig {
    
}

export class AuthModule extends AbstractFw24Module {
    readonly logger: ILogger = createLogger(CognitoStack.name);

    protected stacks: Map<string, IStack>; 

    // array of type of stacks that this stack is dependent on
    dependencies: string[] = [];

    constructor( protected readonly config: IAuthModuleConfig){
        super(config);
        this.stacks = new Map();

        if(config.groups){
            const autoUserSignupHandler: LambdaFunctionProps = {
                entry: join(__dirname,'functions/auto-post-confirmation.js')
            }
            config.groups.filter(group => group.autoUserSignup).map(group => Object.assign(group, {autoUserSignupHandler: autoUserSignupHandler}));
        }
        this.logger.debug("AuthModule: ", config);
        const cognito = new CognitoStack({	
            name: 'authmodule',
            ...config,
        });

        this.stacks.set('auth-cognito', cognito );

    }

    getName(): string {
        return 'AuthModule';
    }

    getBasePath(): string {
        return __dirname;
    }

    getStacks(): Map<string, IStack> {
        return this.stacks;
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