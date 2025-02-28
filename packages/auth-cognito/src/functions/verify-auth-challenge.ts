import { VerifyAuthChallengeResponseTriggerEvent } from 'aws-lambda';

export const handler = async (event: VerifyAuthChallengeResponseTriggerEvent) => {
    const expectedOtp = event.request.privateChallengeParameters?.otp;
    const providedOtp = event.request.challengeAnswer;

    event.response.answerCorrect = expectedOtp === providedOtp;

    return event;
}; 