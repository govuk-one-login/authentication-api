package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.claims.ClaimType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.entity.ValidScopes;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.NoSuchElementException;

import static com.nimbusds.langtag.LangTagUtils.parseLangTagList;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class WellknownHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(WellknownHandler.class);

    private final String providerMetadata;

    public WellknownHandler(ConfigurationService configService) {
        providerMetadata = constructProviderMetadata(configService);
    }

    public WellknownHandler() {
        providerMetadata = constructProviderMetadata(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return segmentedFunctionCall(
                "oidc-api::" + getClass().getSimpleName(),
                () -> wellknownRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent wellknownRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        LOG.info("Wellknown request received");
        return generateApiGatewayProxyResponse(200, providerMetadata);
    }

    private String constructProviderMetadata(ConfigurationService configService) {
        try {
            var baseUrl = configService.getOidcApiBaseURL().orElseThrow();
            var oidcMetadata =
                    new OIDCProviderMetadata(
                            new Issuer(baseUrl),
                            List.of(SubjectType.PUBLIC, SubjectType.PAIRWISE),
                            buildURI(baseUrl, "/.well-known/jwks.json"));
            oidcMetadata.setTokenEndpointURI(buildURI(baseUrl, "/token"));
            oidcMetadata.setUserInfoEndpointURI(buildURI(baseUrl, "/userinfo"));
            oidcMetadata.setAuthorizationEndpointURI(buildURI(baseUrl, "/authorize"));
            oidcMetadata.setRegistrationEndpointURI(buildURI(baseUrl, "/connect/register"));
            oidcMetadata.setTokenEndpointAuthMethods(
                    List.of(ClientAuthenticationMethod.PRIVATE_KEY_JWT));
            oidcMetadata.setScopes(new Scope(ValidScopes.getScopesForWellKnownHandler()));
            oidcMetadata.setResponseTypes(List.of(new ResponseType("code")));
            oidcMetadata.setGrantTypes(List.of(GrantType.AUTHORIZATION_CODE));
            oidcMetadata.setClaimTypes(List.of(ClaimType.NORMAL));
            oidcMetadata.setClaims(ValidClaims.allOneLoginClaims());
            oidcMetadata.setSupportsRequestURIParam(false);
            oidcMetadata.setSupportsRequestParam(true);
            oidcMetadata.setIDTokenJWSAlgs(
                    configService.isRsaSigningAvailable()
                            ? List.of(JWSAlgorithm.ES256, JWSAlgorithm.RS256)
                            : List.of(JWSAlgorithm.ES256));
            oidcMetadata.setTokenEndpointJWSAlgs(
                    List.of(
                            JWSAlgorithm.RS256,
                            JWSAlgorithm.RS384,
                            JWSAlgorithm.RS512,
                            JWSAlgorithm.PS256,
                            JWSAlgorithm.PS384,
                            JWSAlgorithm.PS512));
            oidcMetadata.setServiceDocsURI(new URI("https://docs.sign-in.service.gov.uk/"));
            oidcMetadata.setEndSessionEndpointURI(buildURI(baseUrl, "/logout"));
            oidcMetadata.setSupportsBackChannelLogout(true);
            oidcMetadata.setCustomParameter(
                    "trustmarks", buildURI(baseUrl, "/trustmark").toString());

            var frontendUrl = configService.getFrontendBaseUrl();
            oidcMetadata.setPolicyURI(buildURI(frontendUrl, "privacy-notice"));
            oidcMetadata.setTermsOfServiceURI(buildURI(frontendUrl, "terms-and-conditions"));

            oidcMetadata.setUILocales(parseLangTagList("en", "cy"));

            return oidcMetadata.toString();
        } catch (URISyntaxException | NoSuchElementException | LangTagException e) {
            LOG.error("Exception encountered in WellKnownHandler", e);
            throw new RuntimeException(e);
        }
    }
}
