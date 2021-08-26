package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.claims.ClaimType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.entity.ValidScopes;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.NoSuchElementException;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class WellknownHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ConfigurationService configService;

    public WellknownHandler(ConfigurationService configService) {
        this.configService = configService;
    }

    public WellknownHandler() {
        this.configService = new ConfigurationService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            String baseUrl = configService.getBaseURL().orElseThrow();

            var providerMetadata =
                    new OIDCProviderMetadata(
                            new Issuer(baseUrl),
                            List.of(SubjectType.PUBLIC, SubjectType.PAIRWISE),
                            buildURI("/.well-known/jwks.json", baseUrl));

            providerMetadata.setTokenEndpointURI(buildURI("/token", baseUrl));
            providerMetadata.setUserInfoEndpointURI(buildURI("/userinfo", baseUrl));
            providerMetadata.setAuthorizationEndpointURI(buildURI("/authorize", baseUrl));
            providerMetadata.setRegistrationEndpointURI(buildURI("/connect/register", baseUrl));
            providerMetadata.setTokenEndpointAuthMethods(
                    List.of(ClientAuthenticationMethod.PRIVATE_KEY_JWT));
            providerMetadata.setScopes(ValidScopes.getScopesForWellKnownHandler());
            providerMetadata.setResponseTypes(List.of(new ResponseType("code")));
            providerMetadata.setGrantTypes(List.of(GrantType.AUTHORIZATION_CODE));
            providerMetadata.setClaimTypes(List.of(ClaimType.NORMAL));
            providerMetadata.setClaims(
                    List.of(
                            "sub",
                            "email",
                            "email_verified",
                            "phone_number",
                            "phone_number_verified"));
            providerMetadata.setIDTokenJWSAlgs(List.of(JWSAlgorithm.ES256));
            providerMetadata.setTokenEndpointJWSAlgs(
                    List.of(
                            JWSAlgorithm.RS256,
                            JWSAlgorithm.RS384,
                            JWSAlgorithm.RS512,
                            JWSAlgorithm.PS256,
                            JWSAlgorithm.PS384,
                            JWSAlgorithm.PS512,
                            JWSAlgorithm.ES256,
                            JWSAlgorithm.ES384,
                            JWSAlgorithm.ES512,
                            JWSAlgorithm.HS256,
                            JWSAlgorithm.HS384,
                            JWSAlgorithm.HS512));
            providerMetadata.setServiceDocsURI(new URI("http://TBA"));
            providerMetadata.setEndSessionEndpointURI(buildURI("/logout", baseUrl));

            return generateApiGatewayProxyResponse(200, providerMetadata.toString());
        } catch (URISyntaxException | NoSuchElementException e) {
            return generateApiGatewayProxyResponse(500, "Service not configured");
        }
    }

    private URI buildURI(String prefix, String baseUrl) throws URISyntaxException {
        return new URI(baseUrl + prefix);
    }
}
