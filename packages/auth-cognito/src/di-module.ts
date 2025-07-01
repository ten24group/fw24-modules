import { DIModule } from "@ten24group/fw24";
import { AuthModuleClientDIToken, AuthServiceDIToken } from "./const";
import { CognitoService } from "./services/cognito-service";
import { SharedAuthClient } from "./shared-auth-client";

@DIModule({
  providers: [
    {
      provide: AuthServiceDIToken,
      useClass: CognitoService
    },
    {
      provide: AuthModuleClientDIToken,
      useClass: SharedAuthClient
    }
  ],
  exports: [ AuthModuleClientDIToken ] // allow other modules to use the AuthModuleClient
})
export class AuthModuleDIModule{
}