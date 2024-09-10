import {
	BaseEntityService,
	CreateEntityItemTypeFromSchema,
	createLogger,
	DI_TOKENS,
	DIContainer,
	ILogger,
	Inject,
	InjectContainer,
	Service,
} from '@ten24group/fw24';
import { EntityConfiguration } from 'electrodb';

import { UsersModule } from '../';
import { UserSchemaType } from '../entities/user';
import { UserSchemaDIToken } from '../const';

import { Auth } from "@ten24group/fw24-common";


@Service({providedIn: UsersModule})
export class UserService extends BaseEntityService<UserSchemaType> {

	readonly logger: ILogger = createLogger(UserService);

	constructor(
		@Inject(UserSchemaDIToken) 
		readonly schema: UserSchemaType,
		
		@Inject(DI_TOKENS.DYNAMO_ENTITY_CONFIGURATIONS) 
		readonly entityConfigurations: EntityConfiguration,
		
		@Inject(Auth.AuthModuleClientDIToken, { isOptional: true }) 
		private readonly authModuleClient: Auth.IAuthModuleClient,
		
		@InjectContainer() 
		private readonly container: DIContainer,
	){
		super(schema, entityConfigurations, container);
	}

	public async create( payload: CreateEntityItemTypeFromSchema<UserSchemaType> ) {
		const created = await super.create(payload);

		// create user's auth records
		if(created.data && this.authModuleClient){
			this.logger.info("Creating user auth records for: ", created.data);

			await this.authModuleClient.createUserAuth({
				userId: created.data.userId,
				email: created.data.email,
				password: payload.password,
				groups: ['user'], // TODO: groups support for user
			});

			this.logger.info("Successfully created user auth records for: ", created.data);
		}
		
		return created;
    }
}