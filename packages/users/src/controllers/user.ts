import {BaseEntityController, Controller, type ILogger, Inject, createLogger } from '@ten24group/fw24';
import type { UserSchemaType } from '../entities/user';
import { UserService } from '../services/user';
import { UsersModule } from '..';

@Controller('user', {
	authorizer: [
		{ type: 'AWS_IAM', groups: ['admin'] },
	],
	env: [
		{ name: 'userPoolClientID', prefix: 'authmodule' },
		{ name: 'userPoolID', prefix: 'authmodule' }
	],
	resourceAccess: {
		// TODO: use DI to provide these configurations
		tables: ['users_tbl'] 
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