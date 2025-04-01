export const handler = async (event: any, context: any, callback: any) => {
    // auto verify user
    event.response.autoConfirmUser = true;
    event.response.autoVerifyEmail = true;
    callback(null, event);
};