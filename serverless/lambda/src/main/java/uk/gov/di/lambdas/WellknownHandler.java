package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.claims.ClaimType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;

public class WellknownHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        APIGatewayProxyResponseEvent apiGatewayProxyResponseEvent = new APIGatewayProxyResponseEvent();
        try {
            Optional<String> baseUrl = Optional.ofNullable(context.getClientContext().getEnvironment().get("BASE_URL"));

            var providerMetadata = new OIDCProviderMetadata(new Issuer(baseUrl.orElseThrow()),
                    List.of(SubjectType.PUBLIC), buildURI(".well-known/jwks.json", baseUrl.get()));

            providerMetadata.setTokenEndpointURI(buildURI("token", baseUrl.get()));
            providerMetadata.setUserInfoEndpointURI(buildURI("userinfo", baseUrl.get()));
            providerMetadata.setAuthorizationEndpointURI(buildURI("authorize", baseUrl.get()));
            providerMetadata.setRegistrationEndpointURI(buildURI("connect/register", baseUrl.get()));
            providerMetadata.setTokenEndpointAuthMethods(List.of(ClientAuthenticationMethod.CLIENT_SECRET_POST));
            providerMetadata.setScopes(new Scope("openid", "profile", "email"));
            providerMetadata.setResponseTypes(List.of(new ResponseType("code")));
            providerMetadata.setGrantTypes(List.of(GrantType.AUTHORIZATION_CODE));
            providerMetadata.setClaimTypes(List.of(ClaimType.NORMAL));
            providerMetadata.setClaims(List.of("sub", "gender", "family_name", "given_name", "email"));
            providerMetadata.setIDTokenJWSAlgs(List.of(JWSAlgorithm.RS256));

            apiGatewayProxyResponseEvent.setStatusCode(200);
            apiGatewayProxyResponseEvent.setBody(providerMetadata.toString());
            return apiGatewayProxyResponseEvent;
        } catch (URISyntaxException| NoSuchElementException e) {
            apiGatewayProxyResponseEvent.setStatusCode(500);
            apiGatewayProxyResponseEvent.setBody("Service not configured");
            return apiGatewayProxyResponseEvent;
        }
    }

    private URI buildURI(String prefix, String baseUrl) throws URISyntaxException {
        return new URI(baseUrl + prefix);

    }
}
