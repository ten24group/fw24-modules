# fw24-auth-cognito
Cognito based authentication and authorization module for fw24 project

## Installation

```shell
npm install @ten24group/fw24-auth-cognito
```

## Add module using cli24
Run this from the root of your project

```shell
cli24 add-module auth-cognito
```

## Basic usages
Add auth module with defaults:

```shell
import { AuthModule } from '@ten24group/fw24-auth-cognito';

const authModule = new AuthModule({});
```

## Detail usages
Add auth module with configurations

```shell
import { AuthModule } from '@ten24group/fw24-auth-cognito';

const authModule = new AuthModule({
	userPool: {
		props: {
			userPoolName: 'authmodule'
			selfSignUpEnabled: true,
			// all user pool properties available here: https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.aws_cognito.UserPoolProps.html
		}
	},
	groups: [
		{
			name: 'admin',
			precedence: 0
			policyFilePaths: [
				'./src/policy/admin.json',
			],
			routes: ['mauth/addUserToGroup/', 'mauth/removeUserFromGroup/'],
		},
		{
			name: 'user',
			precedence: 1
			autoUserSignup: true,
			policyFilePaths: [
				'./src/policy/user.json',
			],
		}
	],
	useAsDefaultAuthorizer: true
});

```
