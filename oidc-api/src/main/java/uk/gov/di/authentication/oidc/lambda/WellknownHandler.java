package uk.gov.di.authentication.oidc.lambda;

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.NoSuchElementException;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class WellknownHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LoggerFactory.getLogger(WellknownHandler.class);

    private final ConfigurationService configService;
    private final String baseUrl;
    private OIDCProviderMetadata providerMetadata;

    public WellknownHandler(ConfigurationService configService) {
        this.configService = configService;
        baseUrl = configService.getBaseURL().orElseThrow();
        providerMetadata =
                new OIDCProviderMetadata(
                        new Issuer(baseUrl),
                        List.of(SubjectType.PUBLIC, SubjectType.PAIRWISE),
                        buildURI(baseUrl, "/.well-known/jwks.json"));
    }

    public WellknownHandler() {
        this.configService = new ConfigurationService();
        baseUrl = configService.getBaseURL().orElseThrow();
        providerMetadata =
                new OIDCProviderMetadata(
                        new Issuer(configService.getBaseURL().get()),
                        List.of(SubjectType.PUBLIC, SubjectType.PAIRWISE),
                        buildURI(baseUrl, "/.well-known/jwks.json"));
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            try {
                                providerMetadata.setTokenEndpointURI(buildURI(baseUrl, "/token"));
                                providerMetadata.setUserInfoEndpointURI(
                                        buildURI(baseUrl, "/userinfo"));
                                providerMetadata.setAuthorizationEndpointURI(
                                        buildURI(baseUrl, "/authorize"));
                                providerMetadata.setRegistrationEndpointURI(
                                        buildURI(baseUrl, "/connect/register"));
                                providerMetadata.setTokenEndpointAuthMethods(
                                        List.of(ClientAuthenticationMethod.PRIVATE_KEY_JWT));
                                providerMetadata.setScopes(
                                        ValidScopes.getScopesForWellKnownHandler());
                                providerMetadata.setResponseTypes(
                                        List.of(new ResponseType("code")));
                                providerMetadata.setGrantTypes(
                                        List.of(GrantType.AUTHORIZATION_CODE));
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
                                providerMetadata.setEndSessionEndpointURI(
                                        buildURI(baseUrl, "/logout"));
                                providerMetadata.setCustomParameter(
                                        "trustmarks", buildURI(baseUrl, "/trustmark").toString());

                                return generateApiGatewayProxyResponse(
                                        200, providerMetadata.toString());
                            } catch (URISyntaxException | NoSuchElementException e) {
                                LOG.error("Exception encountered in WellKnownHandler", e);
                                return generateApiGatewayProxyResponse(
                                        500, "Service not configured");
                            }
                        });
    }
}
