# fw24-auth-cognito

The `fw24-auth-cognito` is a robust authentication and authorization module designed specifically for the Framework24 (FW24) project. This module is built on top of AWS Cognito, providing comprehensive user identity management, multi-factor authentication (MFA), and attribute verification capabilities.

## Installation

```shell
npm install @ten24group/fw24-auth-cognito
```

Or using cli24:

```shell
cli24 add-module auth-cognito
```

## Features

- User Management (signup, signin, signout)
- Email and Username Authentication
- Social Authentication (Google, Facebook)
- Account Linking (Email + Social Providers)
- Multi-Factor Authentication (MFA)
- User Attribute Verification
- Password Management
- User Groups and Permissions
- Custom Email Templates
- AWS IAM Integration

## Basic Usage

```typescript
import { AuthModule } from '@ten24group/fw24-auth-cognito';

const authModule = new AuthModule({});
```

## Comprehensive Configuration

```typescript
import { AuthModule } from '@ten24group/fw24-auth-cognito';
import { Mfa, UserPoolEmail, VerificationEmailStyle } from 'aws-cdk-lib/aws-cognito';
import { Duration } from 'aws-cdk-lib';

const authModule = new AuthModule({
  userPool: {
    props: {
      selfSignUpEnabled: true,
      signInAliases: {
        email: true,
        username: true,
      },
      // Configure MFA settings
      mfa: Mfa.OPTIONAL,
      mfaSecondFactor: {
        email: true,
        sms: true,
        otp: false,
      },
      // Configure email settings
      email: UserPoolEmail.withSES({
        sesVerifiedDomain: 'yourdomain.com',
        fromEmail: 'noreply@yourdomain.com',
        sesRegion: 'us-east-1',
      }),
      // Configure verification settings
      userVerification: {
        emailStyle: VerificationEmailStyle.CODE,
        emailSubject: 'Verify your email',
        emailBody: 'Your verification code is {####}',
      }
    }
  },
  // Configure user pool client
  userPoolClient: {
    props: {
      authFlows: {
        user: true,
        userPassword: true,
        adminUserPassword: true,
        custom: true,
      },
      authSessionValidity: Duration.minutes(15),
      preventUserExistenceErrors: true,
    }
  },
  // Configure user groups
  groups: [
    {
      name: 'admin',
      precedence: 0,
      policyFilePaths: ['./src/policy/admin.json'],
      routes: ['mauth/addUserToGroup', 'mauth/removeUserFromGroup'],
    },
    {
      name: 'user',
      precedence: 1,
      autoUserSignup: true,
      policyFilePaths: ['./src/policy/user.json'],
    }
  ],
  // Configure custom message templates
  customMessageTemplates: {
    signup: {
      subject: 'Welcome to Our App',
      message: 'Your verification code is {####}',
    },
    forgotPassword: {
      subject: 'Reset Your Password',
      message: 'Your password reset code is {####}',
    },
    verifyUserAttribute: {
      subject: 'Verify Your Email',
      message: 'Your verification code is {####}',
    },
    authentication: {
      subject: 'Authentication Code',
      message: 'Your authentication code is {####}',
    }
  }
});
```

## Social Authentication Configuration

### Setting up Google OAuth Credentials

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the OAuth consent screen:
   - Go to "APIs & Services" > "OAuth consent screen"
   - Choose "External" user type
   - Fill in the required app information
   - Add the scopes: "email", "profile", "openid"
   - Add test users if in testing mode

4. Create OAuth credentials:
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth client ID"
   - Choose "Web application"
   - Add authorized JavaScript origins:
     ```
     https://{your-cognito-domain}.auth.{region}.amazoncognito.com
     ```
   - Add authorized redirect URIs:
     ```
     https://{your-cognito-domain}.auth.{region}.amazoncognito.com/oauth2/idpresponse
     ```

5. Store your credentials securely:
   - Never commit credentials to version control
   - Use environment variables or AWS Secrets Manager
   - Update your configuration with the credentials:

```typescript
const authModule = new AuthModule({
  userPool: {
    domain: {
      // Optional: specify a custom domain prefix
      cognitoDomainPrefix: 'my-app-auth',
      // Or use a custom domain
      customDomain: {
        domainName: 'auth.example.com',
        certificateArn: 'arn:aws:acm:region:account:certificate/certificate-id'
      }
    },
    socialProviders: {
      google: {
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        scopes: ['email', 'profile', 'openid'],
        attributeMapping: {
          email: 'email',
          givenName: 'given_name',
          familyName: 'family_name',
          picture: 'picture'
        }
      }
    }
  }
});
```

### Setting up Facebook OAuth Credentials

1. Go to the [Meta for Developers](https://developers.facebook.com/)
2. Create a new app or select an existing one:
   - Click "Create App"
   - Choose "Consumer" as the app type
   - Fill in your app name and contact email

3. Configure Facebook Login:
   - From the app dashboard, go to "Add Products"
   - Click "Set Up" on "Facebook Login"
   - Choose "Web" as the platform

4. Configure OAuth settings:
   - Go to "Facebook Login" > "Settings"
   - Add OAuth Redirect URIs:
     ```
     https://{your-cognito-domain}.auth.{region}.amazoncognito.com/oauth2/idpresponse
     ```
   - Under "Client OAuth Settings":
     - Enable "Client OAuth Login"
     - Enable "Web OAuth Login"
     - Add the following to "Valid OAuth Redirect URIs":
       ```
       https://{your-cognito-domain}.auth.{region}.amazoncognito.com/oauth2/idpresponse
       ```

5. Get your credentials:
   - Go to "Settings" > "Basic"
   - Note your App ID (this is your client ID)
   - Click "Show" to view your App Secret (this is your client secret)

6. Configure permissions:
   - Go to "App Review" > "Permissions and Features"
   - Add the following permissions:
     - `email`
     - `public_profile`

7. Update your AuthModule configuration:
```typescript
const authModule = new AuthModule({
  userPool: {
    socialProviders: {
      facebook: {
        clientId: process.env.FACEBOOK_APP_ID,
        clientSecret: process.env.FACEBOOK_APP_SECRET,
        scopes: ['email', 'public_profile'],
        attributeMapping: {
          email: 'email',
          name: 'name',
          picture: 'picture',
          'custom:first_name': 'first_name',
          'custom:last_name': 'last_name'
        }
      }
    },
    domain: {
      cognitoDomainPrefix: 'your-domain-prefix'
    }
  },
  userPoolClient: {
    props: {
      oAuth: {
        flows: {
          authorizationCodeGrant: true
        },
        scopes: ['email', 'openid', 'profile'],
        callbackUrls: ['http://localhost:3000/auth/callback']
      }
    }
  }
});
```

**Attribute Mapping:**
Facebook provides the following attributes that can be mapped to Cognito:
- `id`: Unique Facebook ID
- `email`: User's email address
- `name`: Full name
- `first_name`: First name
- `last_name`: Last name
- `picture`: Profile picture URL
- `gender`: User's gender
- `locale`: User's locale
- `timezone`: User's timezone

You can map these to standard or custom attributes in Cognito using the `attributeMapping` configuration.

### Configure social providers in your AuthModule:

```typescript
const authModule = new AuthModule({
  // ... other config ...
  socialProviders: {
    google: {
      clientId: 'your-google-client-id',
      clientSecret: 'your-google-client-secret',
      scopes: ['email', 'profile', 'openid'],
      attributeMapping: {
        email: 'email',
        givenName: 'given_name',
        familyName: 'family_name',
        picture: 'picture'
      }
    },
    facebook: {
      clientId: 'your-facebook-app-id',
      clientSecret: 'your-facebook-app-secret',
      scopes: ['email', 'public_profile'],
      attributeMapping: {
        email: 'email',
        givenName: 'first_name',
        familyName: 'last_name',
        picture: 'picture'
      }
    }
  },
  userPool: {
    props: {
      // Enable email as sign-in alias for account linking
      signInAliases: {
        email: true
      },
      // Auto-verify email for account linking
      autoVerify: {
        email: true
      },
      // Configure account recovery
      accountRecovery: AccountRecovery.EMAIL_ONLY,
    }
  },
  userPoolClient: {
    props: {
      oAuth: {
        flows: {
          authorizationCodeGrant: true,
          implicitCodeGrant: true,
        },
        scopes: ['email', 'openid', 'profile'],
        callbackUrls: ['http://localhost:3000/auth/callback']
      }
    }
  }
});
```

## Social Authentication APIs

### Get Social Sign-in Configuration
```typescript
POST /mauth/getSocialSignInConfig
{
  "redirectUri": "http://localhost:3000/auth/callback"
}

// Response
{
  "Google": {
    "authorizationUrl": "https://your-cognito-domain.auth.region.amazoncognito.com/oauth2/authorize?...",
    "clientId": "your-client-id",
    "redirectUri": "http://localhost:3000/auth/callback",
    "grantType": "authorization_code"
  },
  "Facebook": {
    "authorizationUrl": "https://your-cognito-domain.auth.region.amazoncognito.com/oauth2/authorize?...",
    "clientId": "your-client-id",
    "redirectUri": "http://localhost:3000/auth/callback",
    "grantType": "authorization_code"
  }
}
```

### Initiate Social Sign-in
```typescript
POST /mauth/initiateSocialSignIn
{
  "provider": "Google",  // or "Facebook"
  "redirectUri": "http://localhost:3000/auth/callback"
}

// Response
{
  "authorizationUrl": "https://your-cognito-domain/oauth2/authorize?..."
}
```

### Complete Social Sign-in
```typescript
POST /mauth/completeSocialSignIn
{
  "provider": "Google",
  "code": "authorization-code-from-callback",
  "redirectUri": "http://localhost:3000/auth/callback"
}

// Response
{
  "AccessToken": "access-token",
  "IdToken": "id-token",
  "RefreshToken": "refresh-token",
  "TokenType": "Bearer",
  "ExpiresIn": 3600,
  "isNewUser": false,
  "provider": "Google"
}
```

### Link Social Provider
```typescript
POST /mauth/linkSocialProvider
{
  "accessToken": "user-access-token",
  "provider": "Google",
  "code": "authorization-code-from-oauth",
  "redirectUri": "http://localhost:3000/auth/callback"
}

// Response
{
  "message": "Social provider linked successfully",
  "provider": "Google"
}
```

### Unlink Social Provider
```typescript
POST /mauth/unlinkSocialProvider
{
  "accessToken": "user-access-token",
  "provider": "Google"
}

// Response
{
  "message": "Social provider unlinked successfully",
  "provider": "Google"
}
```

## Account Linking Scenarios

### Scenario 1: Email First, Then Social
1. User signs up with email/password
2. User later decides to link their social account
3. User initiates social sign-in
4. If the social account's email matches the existing account:
   - The accounts are automatically linked
   - User can now sign in with either method

### Scenario 2: Social First, Then Email
1. User signs up with social provider
2. User's email is verified automatically
3. User can set up password through:
   - Forgot password flow
   - Or admin setting temporary password
4. User can now sign in with either method

## Authentication APIs

### User Registration and Verification

#### Sign Up
```typescript
// Sign up with email
POST /mauth/signup
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}

// Sign up with username
{
  "username": "johndoe",
  "password": "SecurePassword123!"
}

// Sign up with both
{
  "username": "johndoe",
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

#### Verify Email
```typescript
POST /mauth/verify
{
  "email": "user@example.com",
  "code": "123456"
}
```

#### Resend Verification Code
```typescript
POST /mauth/resendVerificationCode
{
  "email": "user@example.com"
}
// or
{
  "username": "johndoe"
}
```

### User Authentication

#### Get Login Options
```typescript
POST /mauth/getLoginOptions
{
  "username": "user@example.com"
}
```

#### Sign In
```typescript
POST /mauth/signin
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
// or
{
  "username": "johndoe",
  "password": "SecurePassword123!"
}
```

#### Sign Out
```typescript
POST /mauth/signout
{
  "accessToken": "user-access-token"
}
```

### Multi-Factor Authentication (MFA)

#### Initiate OTP Authentication
```typescript
POST /mauth/initiateOtpAuth
{
  "username": "user@example.com",
  "session": "session-token-from-getLoginOptions"
}
```

#### Complete OTP Authentication
```typescript
POST /mauth/respondToOtpChallenge
{
  "username": "user@example.com",
  "session": "session-token",
  "code": "123456"
}
```

#### Update User MFA Preferences
```typescript
POST /mauth/updateUserMfaPreference
{
  "accessToken": "user-access-token",
  "mfaPreference": {
    "enabledMethods": ["EMAIL", "SMS"],
    "preferredMethod": "EMAIL"
  }
}
```

### User Attribute Management

#### Get Attribute Verification Code
```typescript
POST /mauth/getUserAttributeVerificationCode
{
  "accessToken": "user-access-token",
  "attributeName": "email"
}
```

#### Verify User Attribute
```typescript
POST /mauth/verifyUserAttribute
{
  "accessToken": "user-access-token",
  "attributeName": "email",
  "code": "123456"
}
```

### Password Management

#### Change Password
```typescript
POST /mauth/changePassword
{
  "accessToken": "user-access-token",
  "oldPassword": "OldPassword123!",
  "newPassword": "NewPassword456!"
}
```

#### Forgot Password
```typescript
POST /mauth/forgotPassword
{
  "email": "user@example.com"
}
```

#### Reset Password
```typescript
POST /mauth/confirmForgotPassword
{
  "email": "user@example.com",
  "code": "123456",
  "newPassword": "NewPassword456!"
}
```

### Token Management

#### Refresh Token
```typescript
POST /mauth/refreshToken
{
  "refreshToken": "your-refresh-token"
}
```

#### Get AWS Credentials
```typescript
POST /mauth/getCredentials
{
  "idToken": "cognito-id-token"
}
```

### Group Management (Admin Only)

#### Add User to Group
```typescript
POST /mauth/addUserToGroup
{
  "email": "user@example.com",
  "groupName": "admin"
}
```

#### Set User MFA Settings (Admin)
```typescript
POST /mauth/setUserMfaSettings
{
  "username": "user@example.com",
  "enabledMethods": ["EMAIL", "SMS"],
  "preferredMethod": "EMAIL"
}
```

## Customizing Email Templates

You can customize various email templates through the `customMessageTemplates` configuration:

```typescript
customMessageTemplates: {
  signup: {
    subject: 'Welcome to Our App',
    message: 'Your verification code is {####}',
  },
  adminCreateUser: {
    subject: 'Your temporary password',
    message: 'Your temporary password is {####}',
  },
  resendCode: {
    subject: 'New verification code',
    message: 'Your new verification code is {####}',
  },
  forgotPassword: {
    subject: 'Reset your password',
    message: 'Use this code to reset your password: {####}',
  },
  verifyUserAttribute: {
    subject: 'Verify your email',
    message: 'Use this code to verify your email: {####}',
  },
  authentication: {
    subject: 'Authentication required',
    message: 'Your authentication code is {####}',
  }
}
```

## Security Best Practices

1. Always use HTTPS for API endpoints
2. Implement proper password policies
3. Enable MFA for sensitive operations
4. Use short-lived access tokens
5. Regularly rotate credentials
6. Monitor authentication attempts
7. Implement rate limiting
8. Use secure session management

## Error Handling

The module provides standardized error responses for various scenarios:

- 400: Bad Request (invalid input)
- 401: Unauthorized (invalid credentials)
- 403: Forbidden (insufficient permissions)
- 404: Not Found
- 429: Too Many Requests
- 500: Internal Server Error

Each error response includes a message explaining the error:

```json
{
  "message": "Error description here"
}
```

## AWS Configuration

Ensure your AWS credentials are properly configured with the necessary permissions for Cognito operations. The module requires the following AWS services:

- Amazon Cognito User Pools
- Amazon Cognito Identity Pools (if using AWS IAM authentication)
- Amazon SES (if using custom email templates)
- IAM roles and policies

## Additional Resources

- [AWS Cognito Documentation](https://docs.aws.amazon.com/cognito/)
- [Framework24 Documentation](https://framework24.io)
- [Security Best Practices](https://docs.aws.amazon.com/cognito/latest/developerguide/security-best-practices.html)
