package uk.gov.di.orchestration.local;

import io.javalin.Javalin;
import uk.gov.di.authentication.app.lambda.DocAppCallbackHandler;
import uk.gov.di.authentication.clientregistry.lambda.ClientRegistrationHandler;
import uk.gov.di.authentication.clientregistry.lambda.UpdateClientConfigHandler;
import uk.gov.di.authentication.ipv.lambda.IPVCallbackHandler;
import uk.gov.di.authentication.ipv.lambda.IpvJwksHandler;
import uk.gov.di.authentication.oidc.lambda.AuthCodeHandler;
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
        var app = Javalin.create();

        // OIDC API
        app.get("/.well-known/jwks.json", handlerFor(new JwksHandler()));
        app.get("/.well-known/openid-configuration", handlerFor(new WellknownHandler()));
        app.get("/.well-known/storage-token-jwk.json", handlerFor(new StorageTokenJwkHandler()));
        app.get("/authorize", handlerFor(new AuthorisationHandler()));
        app.get("/auth-code", handlerFor(new AuthCodeHandler()));
        app.get("/logout", handlerFor(new LogoutHandler()));
        app.get("/orchestration-redirect", handlerFor(new AuthenticationCallbackHandler()));
        app.post("/token", handlerFor(new TokenHandler()));
        app.get("/trustmark", handlerFor(new TrustMarkHandler()));
        app.get("/userinfo", handlerFor(new UserInfoHandler()));
        // TODO: backchannel logout - queue based

        // IPV API
        app.get("./well-known/ipv-jwks.json", handlerFor(new IpvJwksHandler()));
        app.get("/ipv-callback", handlerFor(new IPVCallbackHandler()));
        // TODO: IPV Capacity (deprecated)
        // TODO: Identity progress and processing identity (deprecated?)
        // TODO: SPOT response processing - queue based

        // Doc checking app API
        app.get("/doc-app-callback", handlerFor(new DocAppCallbackHandler()));

        // Client Registry API
        app.post("/connect/register", handlerFor(new ClientRegistrationHandler()));
        app.put("/connect/register/{clientId}", handlerFor(new UpdateClientConfigHandler()));

        // Start app
        app.start(getPort());
    }

    private int getPort() {
        var envPort = System.getenv("PORT");
        return envPort == null ? DEFAULT_PORT : Integer.parseInt(envPort);
    }
}
