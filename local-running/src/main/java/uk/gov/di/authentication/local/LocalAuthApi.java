package uk.gov.di.authentication.local;

import io.javalin.Javalin;
import uk.gov.di.authentication.external.lambda.TokenHandler;
import uk.gov.di.authentication.external.lambda.UserInfoHandler;
import uk.gov.di.authentication.frontendapi.lambda.AccountInterventionsHandler;
import uk.gov.di.authentication.frontendapi.lambda.AccountRecoveryHandler;
import uk.gov.di.authentication.frontendapi.lambda.AuthenticationAuthCodeHandler;
import uk.gov.di.authentication.frontendapi.lambda.CheckEmailFraudBlockHandler;
import uk.gov.di.authentication.frontendapi.lambda.CheckReAuthUserHandler;
import uk.gov.di.authentication.frontendapi.lambda.CheckUserExistsHandler;
import uk.gov.di.authentication.frontendapi.lambda.FinishPasskeyAssertionHandler;
import uk.gov.di.authentication.frontendapi.lambda.IDReverificationStateHandler;
import uk.gov.di.authentication.frontendapi.lambda.LoginHandler;
import uk.gov.di.authentication.frontendapi.lambda.MfaHandler;
import uk.gov.di.authentication.frontendapi.lambda.MfaResetAuthorizeHandler;
import uk.gov.di.authentication.frontendapi.lambda.MfaResetJarJwkHandler;
import uk.gov.di.authentication.frontendapi.lambda.MfaResetStorageTokenJwkHandler;
import uk.gov.di.authentication.frontendapi.lambda.ResetPasswordHandler;
import uk.gov.di.authentication.frontendapi.lambda.ResetPasswordRequestHandler;
import uk.gov.di.authentication.frontendapi.lambda.ReverificationResultHandler;
import uk.gov.di.authentication.frontendapi.lambda.SendNotificationHandler;
import uk.gov.di.authentication.frontendapi.lambda.SignUpHandler;
import uk.gov.di.authentication.frontendapi.lambda.StartHandler;
import uk.gov.di.authentication.frontendapi.lambda.StartPasskeyAssertionHandler;
import uk.gov.di.authentication.frontendapi.lambda.UpdateProfileHandler;
import uk.gov.di.authentication.frontendapi.lambda.VerifyCodeHandler;
import uk.gov.di.authentication.frontendapi.lambda.VerifyMfaCodeHandler;

import static uk.gov.di.authentication.local.handlers.ApiGatewayLambdaHandler.handlerFor;

public class LocalAuthApi {
    private static final int DEFAULT_PORT = 4402;

    // These path mappings must match those in the infrastructure-as-code configuration
    public LocalAuthApi() {
        var app = Javalin.create();

        // Frontend API
        app.get("/mfa-reset-jwk.json", handlerFor(new MfaResetStorageTokenJwkHandler()));
        app.get("/reverification-jwk.json", handlerFor(new MfaResetJarJwkHandler()));

        app.post("/account-interventions", handlerFor(new AccountInterventionsHandler()));
        app.post("/account-recovery", handlerFor(new AccountRecoveryHandler()));
        app.post("/orch-auth-code", handlerFor(new AuthenticationAuthCodeHandler()));
        app.post("/check-email-fraud-block", handlerFor(new CheckEmailFraudBlockHandler()));
        app.post("/check-reauth-user", handlerFor(new CheckReAuthUserHandler()));
        app.post("/id-reverification-state", handlerFor(new IDReverificationStateHandler()));
        app.post("/login", handlerFor(new LoginHandler()));
        app.post("/mfa", handlerFor(new MfaHandler()));
        app.post("/mfa-reset-authorize", handlerFor(new MfaResetAuthorizeHandler()));
        app.post("/reset-password-request", handlerFor(new ResetPasswordRequestHandler()));
        app.post("/reset-password", handlerFor(new ResetPasswordHandler()));
        app.post("/reverification-result", handlerFor(new ReverificationResultHandler()));
        app.post("/send-notification", handlerFor(new SendNotificationHandler()));
        app.post("/signup", handlerFor(new SignUpHandler()));
        app.post("/start", handlerFor(new StartHandler()));
        app.post("/update-profile", handlerFor(new UpdateProfileHandler()));
        app.post("/user-exists", handlerFor(new CheckUserExistsHandler()));
        app.post("/verify-code", handlerFor(new VerifyCodeHandler()));
        app.post("/verify-mfa-code", handlerFor(new VerifyMfaCodeHandler()));
        app.post("/start-passkey-assertion", handlerFor(new StartPasskeyAssertionHandler()));
        app.post("/finish-passkey-assertion", handlerFor(new FinishPasskeyAssertionHandler()));

        // External API
        app.post("/token", handlerFor(new TokenHandler()));
        app.get("/userinfo", handlerFor(new UserInfoHandler()));

        // Start app
        app.start(getPort());
    }

    private int getPort() {
        var envPort = System.getenv("PORT");
        return envPort == null ? DEFAULT_PORT : Integer.parseInt(envPort);
    }
}
