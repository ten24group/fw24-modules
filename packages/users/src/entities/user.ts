import { randomUUID } from 'crypto';

import {
	DefaultEntityOperations,
	EntityIdentifiersTypeFromSchema,
	EntityTypeFromSchema,
	Narrow,
	TEntityOpsInputSchemas,
	createEntitySchema,
	EntityInputValidations,
} from '@ten24group/fw24';

export const createUserSchema = () => createEntitySchema({
	model: {
		version: '1',
		entity: 'User',
		entityNamePlural: 'Users',
		entityOperations: DefaultEntityOperations,
		service: 'users' // electro DB service name [logical group of entities]
	},
	attributes: {
		userId: {
			type: 'string',
			required: true,
			readOnly: true,
			isIdentifier: true,
			default: () => randomUUID()
		},
		firstName: {
			type: 'string',
			required: true,
		},
		lastName: {
			type: 'string',
		},
		email: {
			type: 'string',
			required: true,
		},
		password: {
			type: 'string',
			fieldType: 'password',
			required: true,
		},
		createdAt: {
			// will be set once at the time of create
			type: "string",
			readOnly: true,
			required: true,
			default: () => new Date().toISOString(),
			set: () => new Date().toISOString(),
		},
		updatedAt:{
			type: "string",
			watch: "*", // will be set every time any prop is updated
			required: true,
			readOnly: true,
			default: () => new Date().toISOString(),
			set: () => new Date().toISOString(),
		},
	},
	indexes: {
		primary: {
			pk: {
				field: 'pk',
				composite: ['userId'],
			},
			sk: {
				field: 'sk',
				composite: [],
			},
		},
		byEmail: {
			index: 'gsi1',
			pk: {
				field: 'gsi1pk',
				composite: ['email'],
			},
			sk: {
				field: 'gsi1sk',
				composite: [],
			},
		},
	},

} as const);

export type UserSchemaType = ReturnType<typeof createUserSchema>
export type UserEntityType = EntityTypeFromSchema<UserSchemaType>

export type TUserIdentifiers = Narrow<EntityIdentifiersTypeFromSchema<UserSchemaType>>;
export type TUserOpsInputSchemas = Narrow<TEntityOpsInputSchemas<UserSchemaType>>

export const UserValidationConditions =  {
    emailIsNitin: { 
		input: { 
			email: { eq: 'nitin@gmail.com' }
		}
	}
} as const;

export const UserValidations: EntityInputValidations<UserSchemaType> = {
	firstName: [{
		operations: ['create'],
		required: true,
		minLength: 2,
		maxLength: 10,
		notInList: ['Abc', 'Xyz'],
	}],
	password: [{
		required: true,
		minLength: 8,
		operations: ['create']
	}],
} as const;