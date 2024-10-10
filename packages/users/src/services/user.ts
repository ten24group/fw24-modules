import {
	BaseEntityService,
	CreateEntityItemTypeFromSchema,
	createLogger,
	DI_TOKENS,
	DIContainer,
	EntityIdentifiersTypeFromSchema,
	EntitySelections,
	ILogger,
	Inject,
	InjectContainer,
	Service,
	UpdateEntityItemTypeFromSchema,
} from '@ten24group/fw24';
import { EntityConfiguration } from 'electrodb';

import { UsersModule } from '../';
import { UserSchemaType } from '../entities/user';
import { AuthModuleClientDIToken, UserSchemaDIToken } from '../const';
import { type IAuthModuleClient } from '@ten24group/fw24-auth-cognito';

@Service({providedIn: UsersModule})
export class UserService extends BaseEntityService<UserSchemaType> {

	readonly logger: ILogger = createLogger(UserService);

	constructor(
		@Inject(UserSchemaDIToken) 
		readonly schema: UserSchemaType,
		
		@Inject(DI_TOKENS.DYNAMO_ENTITY_CONFIGURATIONS) 
		readonly entityConfigurations: EntityConfiguration,
		
		@Inject(AuthModuleClientDIToken, { isOptional: true }) 
		private readonly authModuleClient: IAuthModuleClient,
		
		@InjectContainer() 
		private readonly container: DIContainer,
	){
		super(schema, entityConfigurations, container);
	}
	public getDefaultSerializationAttributeNames(): EntitySelections<UserSchemaType>{
		const ss = super.getDefaultSerializationAttributeNames(); 
		return (ss as Array<string>).filter((s) => s !== 'password');
	}

	public async create( payload: CreateEntityItemTypeFromSchema<UserSchemaType> ) {
		const created = await super.create(payload);

		// create user's auth records
		if(created.data && this.authModuleClient){

			this.logger.info("Creating user auth records for: ", created.data);

			await this.authModuleClient.createUserAuth({
				username: payload.email,
				password: payload.password,
				groups: [ payload.group ]
			});

			this.logger.info("Successfully created user auth records for: ", created.data);
		}
		
		return created;
    }

	public async update(
		identifiers: EntityIdentifiersTypeFromSchema<UserSchemaType>, 
		data: UpdateEntityItemTypeFromSchema<UserSchemaType>
	): Promise<any> {
		
		const updated = await super.update(identifiers, data);

		const user = await super.get({identifiers});

		if(data.group){
			await this.authModuleClient.setUserGroups({
				username: user!.email,
				groups: [ data.group ]
			});
		}

		return updated;
    }
}