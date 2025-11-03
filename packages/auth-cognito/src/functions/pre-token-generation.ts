/**
 * Pre Token Generation Lambda Trigger
 *
 * This trigger is invoked by Cognito before generating ID and Access tokens.
 * It adds custom claims to the tokens, specifically the custom:userId attribute.
 *
 * This allows us to include the database userId directly in the JWT token,
 * eliminating the need for additional Cognito API calls or DynamoDB queries
 * when retrieving the current user.
 *
 * Trigger runs on:
 * - Initial sign-in (password/OTP)
 * - Social sign-in (Google/Facebook)
 * - Refresh token flow
 * - Get credentials flow
 */
export const handler = async (event: any) => {
    console.info('🎫 PRE_TOKEN_GENERATION trigger called');
    console.info('📝 Trigger source:', event.triggerSource);
    console.info('👤 Username:', event.userName);
    console.info('📧 User attributes:', JSON.stringify(event.request.userAttributes, null, 2));

    try {
        // Extract custom:userId from user attributes
        const customUserId = event.request.userAttributes['custom:userId'];

        if (customUserId) {
            // Add userId to the ID token claims
            // This makes it available in the JWT without the "custom:" prefix
            event.response = {
                claimsOverrideDetails: {
                    claimsToAddOrOverride: {
                        'userId': customUserId
                    }
                }
            };

            console.info('✅ Added userId to token claims:', customUserId);
        } else {
            console.warn('⚠️ custom:userId attribute not found for user:', event.userName);
            console.warn('Available attributes:', Object.keys(event.request.userAttributes));
        }

        console.info('🎫 PRE_TOKEN_GENERATION trigger completed');
        return event;
    } catch (error) {
        console.error('❌ Error in pre-token-generation trigger:', error);
        // Return event unchanged to avoid blocking authentication
        return event;
    }
};
