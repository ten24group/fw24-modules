import { DefineAuthChallengeTriggerEvent } from 'aws-lambda';

export const handler = async (event: DefineAuthChallengeTriggerEvent) => {
    if (event.request.session.length === 0) {
        // First challenge - issue OTP
        event.response.challengeName = 'CUSTOM_CHALLENGE';
        event.response.issueTokens = false;
        event.response.failAuthentication = false;
    } else if (event.request.session.length === 1 && 
               event.request.session[0].challengeName === 'CUSTOM_CHALLENGE' && 
               event.request.session[0].challengeResult === true) {
        // User successfully answered OTP challenge
        event.response.issueTokens = true;
        event.response.failAuthentication = false;
    } else {
        // User failed or something went wrong
        event.response.issueTokens = false;
        event.response.failAuthentication = true;
    }

    return event;
}; 