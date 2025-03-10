export const handler = async (event: any, context: any, callback: any) => {
    console.log('Auto verify user:', event);
    // auto verify user
    event.response.autoConfirmUser = true;
    event.response.autoVerifyEmail = true;
    callback(null, event);
};