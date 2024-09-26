import {BaseEntityController, Controller, type ILogger, Inject, createLogger } from '@ten24group/fw24';
import type { UserSchemaType } from '../entities/user';
import { UsersModule } from '..';
import { UserService } from '../services/user';
import { Auth } from '@ten24group/fw24-common';
import { USER_MODULE_TABLE_NAME } from '../const';

@Controller('user', {
	authorizer: 
		{ type: 'AWS_IAM', groups: ['admin'] },
	
	env: [
		{ name: 'userPoolClientID', prefix: 'authmodule' },
		{ name: 'userPoolID', prefix: 'authmodule' }
	],
	policies: [ 
		{ 
			name: Auth.AuthModulePolicy_AllowCreateUserAuth,
			prefix: 'AuthModule',
			isOptional: true 
		},
	],
	resourceAccess: {
		// provide the table name from the environment using some convention
		tables: [`env:${UsersModule.name}:${USER_MODULE_TABLE_NAME}`]
	},
	module: { providedBy: UsersModule }
})
export class UserController extends BaseEntityController<UserSchemaType> {	
	readonly logger: ILogger = createLogger(UserController);

	constructor(
		@Inject(UserService) private readonly userService: UserService,
	) {
		super('User', userService);
	}
}