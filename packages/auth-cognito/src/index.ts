import { AbstractFw24Module, AuthConstruct, createLogger, DIModule, FW24Construct, ILogger, LambdaFunctionProps } from '@ten24group/fw24';
import { join } from 'path';

import { AuthServiceDIToken } from './const';
import { IAuthModuleConfig } from './interfaces';
import { CognitoService } from './services/cognito-service';
import { SharedAuthClient } from './shared-auth-client';

import { Auth } from "@ten24group/fw24-common";


@DIModule({
    providers: [
        { 
            provide: AuthServiceDIToken, 
            useClass: CognitoService 
        },
        {
            provide: Auth.AuthModuleClientDIToken,
            useClass: SharedAuthClient
        }
    ],
    exports: [ Auth.AuthModuleClientDIToken ] // allow other modules to use the AuthModuleClient
})
export class AuthModule extends AbstractFw24Module {
    readonly logger: ILogger = createLogger(AuthModule.name);

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
            config.groups.filter(group => group.autoUserSignup)
            .map( group => Object.assign(group, {autoUserSignupHandler}));
        }
        if(config.userPool && !config.userPool.props.userPoolName){
            // set the user pool name
            Object.assign(config.userPool.props, {userPoolName: 'authmodule'});
        } else if (!config.userPool){
            // set the user pool name
            config.userPool = {
                props: {
                    userPoolName: 'authmodule'
                }
            }
        }
        this.logger.debug("AuthModule: ", config);
        
        const cognito = new AuthConstruct({	
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