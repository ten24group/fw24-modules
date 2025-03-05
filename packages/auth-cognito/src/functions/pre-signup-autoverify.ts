export const handler = async (event: any, context: any, callback: any) => {
    console.log('Auto verify user:', event);
    // auto verify user
    event.response.autoConfirmUser = true;
    callback(null, event);
};