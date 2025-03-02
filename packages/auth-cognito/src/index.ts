import { join } from 'path';
import { AbstractFw24Module, AuthConstruct, createLogger, DIModule, FW24Construct, ILogger, LambdaFunctionProps, type ArrayElement } from '@ten24group/fw24';
import { AuthModuleClientDIToken, AuthModulePolicy_AllowCreateUserAuth, AuthServiceDIToken, CUSTOM_MESSAGE_ADMIN_CREATE_USER, CUSTOM_MESSAGE_AUTHENTICATE, CUSTOM_MESSAGE_FORGOT_PASSWORD, CUSTOM_MESSAGE_RESEND_CODE, CUSTOM_MESSAGE_SIGN_UP, CUSTOM_MESSAGE_UPDATE_USER_ATTRIBUTE, CUSTOM_MESSAGE_VERIFY_USER_ATTRIBUTE, CUSTOM_SUBJECT_ADMIN_CREATE_USER, CUSTOM_SUBJECT_AUTHENTICATE, CUSTOM_SUBJECT_FORGOT_PASSWORD, CUSTOM_SUBJECT_RESEND_CODE, CUSTOM_SUBJECT_SIGN_UP, CUSTOM_SUBJECT_UPDATE_USER_ATTRIBUTE, CUSTOM_SUBJECT_VERIFY_USER_ATTRIBUTE } from './const';
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

        // if autoVerifyUser is true, make sure user is automatically verified
        if(config.autoVerifyUser){
            const preSignupTrigger = {
                trigger: 'PRE_SIGN_UP' as const,
                functionProps: {
                    entry: join(__dirname, 'functions/pre-signup-autoverify.js'),
                    policies: []
                }
            }
            config.triggers?.push(preSignupTrigger);
        }

        // Combine all triggers
        const allTriggers = [
            ...(config.triggers ?? []),
        ];

        if(config.customMessageTemplates){
            const customMessageTrigger = this.makeCustomMessageHandlerTrigger(config.customMessageTemplates);
            if (customMessageTrigger) {
                allTriggers.push(customMessageTrigger);
            }
        }

        this.logger.debug("All Triggers: ", allTriggers);
        
        const cognito = new AuthConstruct({	
            ...config,
            triggers: allTriggers,
        });

        this.constructs.set('auth-cognito', cognito );
    }

    makeCustomMessageHandlerTrigger( customMessageTemplates: IAuthModuleConfig['customMessageTemplates']): ArrayElement<IAuthModuleConfig['triggers']> | undefined {
        
        if(!customMessageTemplates){
            return;
        }

        let environmentVariables: any = {};

        if(customMessageTemplates.signup){
            environmentVariables[CUSTOM_MESSAGE_SIGN_UP] = customMessageTemplates.signup.message;
            environmentVariables[CUSTOM_SUBJECT_SIGN_UP] = customMessageTemplates.signup.subject;
        }
        if(customMessageTemplates.resendCode){
            environmentVariables[CUSTOM_MESSAGE_RESEND_CODE] = customMessageTemplates.resendCode.message;
            environmentVariables[CUSTOM_SUBJECT_RESEND_CODE] = customMessageTemplates.resendCode.subject;
        }
        if(customMessageTemplates.adminCreateUser){
            environmentVariables[CUSTOM_MESSAGE_ADMIN_CREATE_USER] = customMessageTemplates.adminCreateUser.message;
            environmentVariables[CUSTOM_SUBJECT_ADMIN_CREATE_USER] = customMessageTemplates.adminCreateUser.subject;
        }
        if(customMessageTemplates.forgotPassword){
            environmentVariables[CUSTOM_MESSAGE_FORGOT_PASSWORD] = customMessageTemplates.forgotPassword.message;
            environmentVariables[CUSTOM_SUBJECT_FORGOT_PASSWORD] = customMessageTemplates.forgotPassword.subject;
        }
        if(customMessageTemplates.authentication){
            environmentVariables[CUSTOM_MESSAGE_AUTHENTICATE] = customMessageTemplates.authentication.message;
            environmentVariables[CUSTOM_SUBJECT_AUTHENTICATE] = customMessageTemplates.authentication.subject;
        }
        if(customMessageTemplates.updateUserAttribute){
            environmentVariables[CUSTOM_MESSAGE_UPDATE_USER_ATTRIBUTE] = customMessageTemplates.updateUserAttribute.message;
            environmentVariables[CUSTOM_SUBJECT_UPDATE_USER_ATTRIBUTE] = customMessageTemplates.updateUserAttribute.subject;
        }
        if(customMessageTemplates.verifyUserAttribute){
            environmentVariables[CUSTOM_MESSAGE_VERIFY_USER_ATTRIBUTE] = customMessageTemplates.verifyUserAttribute.message;
            environmentVariables[CUSTOM_SUBJECT_VERIFY_USER_ATTRIBUTE] = customMessageTemplates.verifyUserAttribute.subject;
        }

        const customMessageHandlerTrigger: ArrayElement<IAuthModuleConfig['triggers']> = {
            functionProps: {
                entry: join(__dirname,'functions/custom-message.js'),
                environmentVariables
            },
            trigger: 'CUSTOM_MESSAGE'
        }

        return customMessageHandlerTrigger;
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
                'cognito-idp:AdminCreateUser',
                'cognito-idp:AdminAddUserToGroup', 
                'cognito-idp:AdminSetUserPassword',
                'cognito-idp:AdminResetUserPassword',
                'cognito-idp:AdminListGroupsForUser',
                'cognito-idp:AdminRemoveUserFromGroup',
                'cognito-idp:AdminUpdateUserAttributes',
            ],
            resources: ['*'],
        });
        return policies;
    }
}