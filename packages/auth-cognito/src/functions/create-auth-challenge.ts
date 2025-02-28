import { CreateAuthChallengeTriggerEvent } from 'aws-lambda';
import { SESClient, SendEmailCommand } from '@aws-sdk/client-ses';

const sesClient = new SESClient({});

export const handler = async (event: CreateAuthChallengeTriggerEvent) => {
    let otp: string;

    if (event.request.challengeName === 'CUSTOM_CHALLENGE') {
        // Generate a random 6-digit OTP
        otp = Math.floor(100000 + Math.random() * 900000).toString();
        
        // Store the OTP in privateChallenge for verification
        event.response.privateChallengeParameters = { otp };
        
        // Don't send the actual OTP in publicChallenge
        event.response.publicChallengeParameters = { 
            email: event.request.userAttributes.email
        };

        // Send OTP via email
        try {
            await sesClient.send(new SendEmailCommand({
                Destination: {
                    ToAddresses: [event.request.userAttributes.email]
                },
                Message: {
                    Body: {
                        Text: {
                            Data: `Your authentication code is: ${otp}`
                        }
                    },
                    Subject: {
                        Data: 'Your authentication code'
                    }
                },
                Source: 'aws@ten24.co'
            }));
        } catch (error) {
            console.error('Error sending email:', error);
            throw new Error('Failed to send OTP email');
        }
    }

    return event;
}; 