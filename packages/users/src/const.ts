import { createToken } from "@ten24group/fw24";

// make sure these keys match with auth module keys
export const AuthModuleClientDIToken = createToken('AuthModuleClient'); 
export const AuthModulePolicy_AllowCreateUserAuth = 'Policy:AllowCreateUserAuth';


export const TABLE_NAME_KEY = 'USER_MODULE_TABLE_NAME';
export const NEW_USER_GROUPS_KEY = 'USER_MODULE_NEW_USER_GROUPS';
export const ADMIN_USER_GROUPS_KEY = 'USER_MODULE_ADMIN_USER_GROUPS';