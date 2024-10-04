import {BaseEntityController, Controller, Get, type ILogger, type Request, type Response, Inject, createLogger, toHumanReadableName } from '@ten24group/fw24';
import type { UserSchemaType } from '../entities/user';
import { UsersModule } from '..';
import { UserService } from '../services/user';
import { AuthModulePolicy_AllowCreateUserAuth, USER_MODULE_NEW_USER_GROUPS, USER_MODULE_TABLE_NAME, USER_MODULE_USER_APIS_AUTH_GROUPS } from '../const';

@Controller('user', {
	authorizer: { 
		type: 'AWS_IAM', 
		groups: `env:${UsersModule.name}:${USER_MODULE_USER_APIS_AUTH_GROUPS}` 
	},

	env: [
		{ name: 'userPoolClientID', prefix: 'authmodule' },
		{ name: 'userPoolID', prefix: 'authmodule' },
		{ name: `${USER_MODULE_NEW_USER_GROUPS}`, prefix: UsersModule.name, }
	],
	policies: [ 
		{ 
			name: AuthModulePolicy_AllowCreateUserAuth,
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

	@Get('/new-user-group-options')
	getNewUserGroupOptions(req: Request, res: Response): Response {

		let groups = process.env[USER_MODULE_NEW_USER_GROUPS]?.split(',') || [];

		this.logger.info("process env groups: ", groups);

		const groupOptions = groups.map( 
			g => ({ label: toHumanReadableName(g), value: g })
		);

		this.logger.info("Returning new user group options: ", groupOptions);

		return res.json({ groups: groupOptions });
	}
}