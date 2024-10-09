import { join } from 'path';
import { AbstractFw24Module, AuthConstruct, createLogger, DIModule, FW24Construct, ILogger, LambdaFunctionProps } from '@ten24group/fw24';
import { AuthModuleClientDIToken, AuthModulePolicy_AllowCreateUserAuth, AuthServiceDIToken } from './const';
import { IAuthModuleConfig } from './interfaces';
import { CognitoService } from './services/cognito-service';
import { SharedAuthClient } from './shared-auth-client';

export * from './interfaces'

@DIModule({
    providers: [
        { 
            provide: AuthServiceDIToken, 
            useClass: CognitoService 
        },
        {
            provide: AuthModuleClientDIToken,
            useClass: SharedAuthClient
        }
    ],
    exports: [ AuthModuleClientDIToken ] // allow other modules to use the AuthModuleClient
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

    getBasePath(): string {
        return __dirname;
    }

    getConstructs(): Map<string, FW24Construct> {
        return this.constructs;
    }

    getDependencies(): string[] {
        return this.dependencies;
    }

    getExportedPolicies() {
        const policies = new Map();
        policies.set(AuthModulePolicy_AllowCreateUserAuth, {
            actions: [
                'cognito-idp:AdminAddUserToGroup', 
                'cognito-idp:AdminListGroupsForUser',
                'cognito-idp:AdminRemoveUserFromGroup',
            ],
            resources: ['*'],
        });
        return policies;
    }
}