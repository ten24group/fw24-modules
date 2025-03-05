import { jest, expect } from '@jest/globals';
import 'aws-sdk-client-mock-jest';

// Create a proper Response object for the mock
const responseData = {
    access_token: 'test-access-token',
    id_token: 'test-id-token',
    refresh_token: 'test-refresh-token',
    token_type: 'Bearer',
    expires_in: 3600
};

// Set up the fetch mock with proper typing
const mockFetch = jest.fn().mockImplementation(() => {
    return Promise.resolve(new Response(JSON.stringify(responseData), {
        status: 200,
        statusText: 'OK',
        headers: new Headers({
            'Content-Type': 'application/json'
        })
    }));
});

global.fetch = mockFetch as unknown as typeof fetch;

// Mock environment variables
process.env.AWS_REGION = 'us-east-1';
process.env.USER_POOL_ID = 'us-east-1_testpool';
process.env.USER_POOL_CLIENT_ID = 'test-client-id';
process.env.IDENTITY_POOL_ID = 'us-east-1:test-identity-pool';
process.env.AUTH_DOMAIN = 'test-domain.auth.us-east-1.amazoncognito.com';

// Mock resolveEnvValueFor function from fw24
const mockResolveEnvValueFor = jest.fn(({ key }: { key: string }) => {
    const envMap: { [key: string]: string } = {
        userPoolID: process.env.USER_POOL_ID || '',
        userPoolClientID: process.env.USER_POOL_CLIENT_ID || '',
        identityPoolID: process.env.IDENTITY_POOL_ID || '',
        authDomain: process.env.AUTH_DOMAIN || '',
        supportedIdentityProviders: 'Google,Facebook'
    };
    return envMap[key] || '';
});

jest.mock('@ten24group/fw24', () => ({
    resolveEnvValueFor: mockResolveEnvValueFor
})); 