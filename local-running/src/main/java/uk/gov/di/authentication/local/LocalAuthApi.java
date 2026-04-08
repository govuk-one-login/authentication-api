package uk.gov.di.authentication.local;

import io.javalin.Javalin;
import uk.gov.di.authentication.external.lambda.TokenHandler;
import uk.gov.di.authentication.external.lambda.UserInfoHandler;
import uk.gov.di.authentication.frontendapi.lambda.AMCAuthorizeHandler;
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
        var app =
                Javalin.create(
                        config -> {
                            // Frontend API
                            config.routes.get(
                                    "/mfa-reset-jwk.json",
                                    handlerFor(new MfaResetStorageTokenJwkHandler()));
                            config.routes.get(
                                    "/reverification-jwk.json",
                                    handlerFor(new MfaResetJarJwkHandler()));

                            config.routes.post(
                                    "/account-interventions",
                                    handlerFor(new AccountInterventionsHandler()));
                            config.routes.post(
                                    "/account-recovery", handlerFor(new AccountRecoveryHandler()));
                            config.routes.post(
                                    "/orch-auth-code",
                                    handlerFor(new AuthenticationAuthCodeHandler()));
                            config.routes.post(
                                    "/check-email-fraud-block",
                                    handlerFor(new CheckEmailFraudBlockHandler()));
                            config.routes.post(
                                    "/check-reauth-user", handlerFor(new CheckReAuthUserHandler()));
                            config.routes.post(
                                    "/id-reverification-state",
                                    handlerFor(new IDReverificationStateHandler()));
                            config.routes.post("/login", handlerFor(new LoginHandler()));
                            config.routes.post("/mfa", handlerFor(new MfaHandler()));
                            config.routes.post(
                                    "/amc-authorize", handlerFor(new AMCAuthorizeHandler()));
                            config.routes.post(
                                    "/mfa-reset-authorize",
                                    handlerFor(new MfaResetAuthorizeHandler()));
                            config.routes.post(
                                    "/reset-password-request",
                                    handlerFor(new ResetPasswordRequestHandler()));
                            config.routes.post(
                                    "/reset-password", handlerFor(new ResetPasswordHandler()));
                            config.routes.post(
                                    "/reverification-result",
                                    handlerFor(new ReverificationResultHandler()));
                            config.routes.post(
                                    "/send-notification",
                                    handlerFor(new SendNotificationHandler()));
                            config.routes.post("/signup", handlerFor(new SignUpHandler()));
                            config.routes.post("/start", handlerFor(new StartHandler()));
                            config.routes.post(
                                    "/update-profile", handlerFor(new UpdateProfileHandler()));
                            config.routes.post(
                                    "/user-exists", handlerFor(new CheckUserExistsHandler()));
                            config.routes.post("/verify-code", handlerFor(new VerifyCodeHandler()));
                            config.routes.post(
                                    "/verify-mfa-code", handlerFor(new VerifyMfaCodeHandler()));
                            config.routes.post(
                                    "/start-passkey-assertion",
                                    handlerFor(new StartPasskeyAssertionHandler()));
                            config.routes.post(
                                    "/finish-passkey-assertion",
                                    handlerFor(new FinishPasskeyAssertionHandler()));

                            // External API
                            config.routes.post("/token", handlerFor(new TokenHandler()));
                            config.routes.get("/userinfo", handlerFor(new UserInfoHandler()));
                        });

        // Start app
        app.start(getPort());
    }

    private int getPort() {
        var envPort = System.getenv("PORT");
        return envPort == null ? DEFAULT_PORT : Integer.parseInt(envPort);
    }
}
