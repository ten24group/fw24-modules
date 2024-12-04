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
			isVisible: false,
			isEditable: false,
			isCreatable: false,
			isIdentifier: true, // this is required to make the listing actions work
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
		group: {
			type: 'string',
			required: true,
			fieldType: 'select',
			options: {
				apiMethod: 'GET',
				apiUrl: '/user/new-user-group-options',
				responseKey: 'groups'
			},
		},
		password: {
			type: 'string',
			required: true,
			isCreatable: true,
			isEditable: false,
			isFilterable: false,
			isListable: false,
			isSearchable: false,
			isSortable: false,
			fieldType: 'password',
			set: () => undefined, // nothing is persisted in our DB
		},
		createdAt: {
			// will be set once at the time of create
			type: "string",
			readOnly: true,
			required: true,
			isCreatable: false,
			isEditable: false,
			isListable: false,
			fieldType: 'datetime',
			name: "Created Date",
			default: () => new Date().toISOString(),
			set: () => new Date().toISOString(),
		},
		updatedAt:{
			type: "string",
			watch: "*", // will be set every time any prop is updated
			readOnly: true,
			isCreatable: false,
			isEditable: false,
			isListable: false,
			fieldType: 'datetime',
			name: "Updated Date",
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