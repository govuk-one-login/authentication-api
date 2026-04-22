package uk.gov.di.orchestration.local;

import io.javalin.Javalin;
import uk.gov.di.authentication.app.lambda.DocAppCallbackHandler;
import uk.gov.di.authentication.clientregistry.lambda.ClientRegistrationHandler;
import uk.gov.di.authentication.clientregistry.lambda.UpdateClientConfigHandler;
import uk.gov.di.authentication.ipv.lambda.IPVCallbackHandler;
import uk.gov.di.authentication.ipv.lambda.IpvJwksHandler;
import uk.gov.di.authentication.oidc.lambda.AuthCodeHandler;
import uk.gov.di.authentication.oidc.lambda.AuthJwksHandler;
import uk.gov.di.authentication.oidc.lambda.AuthenticationCallbackHandler;
import uk.gov.di.authentication.oidc.lambda.AuthorisationHandler;
import uk.gov.di.authentication.oidc.lambda.JwksHandler;
import uk.gov.di.authentication.oidc.lambda.LogoutHandler;
import uk.gov.di.authentication.oidc.lambda.StorageTokenJwkHandler;
import uk.gov.di.authentication.oidc.lambda.TokenHandler;
import uk.gov.di.authentication.oidc.lambda.TrustMarkHandler;
import uk.gov.di.authentication.oidc.lambda.UserInfoHandler;
import uk.gov.di.authentication.oidc.lambda.WellknownHandler;

import static uk.gov.di.orchestration.local.handlers.ApiGatewayLambdaHandler.handlerFor;

public class LocalOrchestrationApi {
    private static final int DEFAULT_PORT = 4400;

    // These path mappings must match those in the infrastructure-as-code configuration
    public LocalOrchestrationApi() {
        var app = Javalin.create(config -> {

                    // OIDC API
                    config.routes.get("/.well-known/jwks.json", handlerFor(new JwksHandler()));
                    config.routes.get("/.well-known/openid-configuration", handlerFor(new WellknownHandler()));
                    config.routes.get("/.well-known/storage-token-jwk.json", handlerFor(new StorageTokenJwkHandler()));
                    config.routes.get("/authorize", handlerFor(new AuthorisationHandler()));
                    config.routes.get("/auth-code", handlerFor(new AuthCodeHandler()));
                    config.routes.post("/token", handlerFor(new TokenHandler()));
                    config.routes.get("/userinfo", handlerFor(new UserInfoHandler()));
                    config.routes.get("/logout", handlerFor(new LogoutHandler()));
                    config.routes.get("/trustmark", handlerFor(new TrustMarkHandler()));
                    // TODO: backchannel logout - set up queue poll

                    // Auth API
                    config.routes.get(".well-known/auth-jwks.json", handlerFor(new AuthJwksHandler()));
                    config.routes.get("/orchestration-redirect", handlerFor(new AuthenticationCallbackHandler()));

                    // IPV API
                    config.routes.get("./well-known/ipv-jwks.json", handlerFor(new IpvJwksHandler()));
                    config.routes.get("/ipv-callback", handlerFor(new IPVCallbackHandler()));
                    // TODO: IPV Capacity (deprecated)
                    // TODO: Identity progress and processing identity (deprecated?)
                    // TODO: SPOT response processing - set up queue poll

                    // Doc checking app API
                    config.routes.get("/doc-app-callback", handlerFor(new DocAppCallbackHandler()));

                    // Client Registry API
                    config.routes.post("/connect/register", handlerFor(new ClientRegistrationHandler()));
                    config.routes.put("/connect/register/{clientId}", handlerFor(new UpdateClientConfigHandler()));
                });

        // Start app
        app.start(getPort());
    }

    private int getPort() {
        var envPort = System.getenv("PORT");
        return envPort == null ? DEFAULT_PORT : Integer.parseInt(envPort);
    }
}
