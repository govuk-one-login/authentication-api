package uk.gov.di.authentication.api;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.oidc.lambda.AuthorisationHandler;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.ServiceType;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.orchestration.sharedtest.extensions.OrchClientSessionExtension;
import uk.gov.di.orchestration.sharedtest.extensions.OrchSessionExtension;
import uk.gov.di.orchestration.sharedtest.helper.KeyPairHelper;

import java.net.URI;
import java.security.KeyPair;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static com.nimbusds.openid.connect.sdk.OIDCScopeValue.EMAIL;
import static com.nimbusds.openid.connect.sdk.OIDCScopeValue.OPENID;
import static com.nimbusds.openid.connect.sdk.OIDCScopeValue.PHONE;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.oidc.domain.OidcAuditableEvent.AUTHORISATION_INITIATED;
import static uk.gov.di.authentication.oidc.domain.OidcAuditableEvent.AUTHORISATION_REQUEST_PARSED;
import static uk.gov.di.authentication.oidc.domain.OidcAuditableEvent.AUTHORISATION_REQUEST_RECEIVED;
import static uk.gov.di.orchestration.shared.entity.CustomScopeValue.ACCOUNT_MANAGEMENT;
import static uk.gov.di.orchestration.shared.entity.CustomScopeValue.GOVUK_ACCOUNT;
import static uk.gov.di.orchestration.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.orchestration.sharedtest.helper.JsonArrayHelper.jsonArrayOf;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class OrchestrationToAuthenticationAuthorizeIntegrationTest
        extends ApiGatewayHandlerIntegrationTest {

    private static final String CLIENT_ID = "gfdsfdsf7s323hfsd";
    private static final String CLIENT_NAME = "test-client";
    private static final String AUTH_INTERNAL_CLIENT_ID = "authentication-orch-client-id";
    private static final String RP_SECTOR_URI = "https://rp-sector-uri.com";
    private static final String RP_REDIRECT_URI = "https://rp-uri/redirect";
    private static final String ORCHESTRATION_REDIRECT_URI = "https://orchestration/redirect";
    private static final KeyPair KEY_PAIR = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
    private static final String publicKey =
            "-----BEGIN PUBLIC KEY-----\n"
                    + Base64.getMimeEncoder().encodeToString(KEY_PAIR.getPublic().getEncoded())
                    + "\n-----END PUBLIC KEY-----\n";

    private static final ConfigurationService configurationService =
            new OrchestrationToAuthenticationAuthorizeIntegrationTest.TestConfigurationService();

    @RegisterExtension
    public static final OrchSessionExtension orchSessionExtension = new OrchSessionExtension();

    @RegisterExtension
    public static final OrchClientSessionExtension orchClientSessionExtension =
            new OrchClientSessionExtension();

    @BeforeEach
    void setup() {
        handler = new AuthorisationHandler(configurationService, redisConnectionService);
        txmaAuditQueue.clear();
    }

    @Test
    void
            shouldSendSecureJarToAuthenticationWithRelevantScopesAndAddIdentityClaimsWhenIdentityIsRequired()
                    throws ParseException, JOSEException, java.text.ParseException {
        var rpRequestedScopes = new Scope(OPENID, PHONE, EMAIL);
        registerClient(rpRequestedScopes.toStringList(), true);

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(Optional.empty()),
                        constructQueryStringParameters(rpRequestedScopes.toString(), "P2.Cl.Cm"),
                        Optional.of("GET"));

        var claimsRequest = getValidatedClaimsRequest(response);

        assertTrue(Objects.nonNull(claimsRequest.getUserInfoClaimsRequest().get("salt")));
        assertTrue(
                Objects.nonNull(claimsRequest.getUserInfoClaimsRequest().get("local_account_id")));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        AUTHORISATION_REQUEST_RECEIVED,
                        AUTHORISATION_REQUEST_PARSED,
                        AUTHORISATION_INITIATED));
    }

    @Test
    void
            shouldSendSecureJarToAuthenticationWithRelevantScopesAndAddAccountManagementClaimWhenAmScopeIsPresent()
                    throws ParseException, JOSEException, java.text.ParseException {
        var rpRequestedScopes = new Scope(OPENID, EMAIL, ACCOUNT_MANAGEMENT);
        registerClient(rpRequestedScopes.toStringList(), false);

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(Optional.empty()),
                        constructQueryStringParameters(rpRequestedScopes.toString(), null),
                        Optional.of("GET"));

        var claimsRequest = getValidatedClaimsRequest(response);

        assertTrue(
                Objects.nonNull(claimsRequest.getUserInfoClaimsRequest().get("public_subject_id")));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        AUTHORISATION_REQUEST_RECEIVED,
                        AUTHORISATION_REQUEST_PARSED,
                        AUTHORISATION_INITIATED));
    }

    @Test
    void
            shouldSendSecureJarToAuthenticationWithRelevantScopesAndAddPhoneClaimsWhenPhoneScopeIsPresent()
                    throws ParseException, JOSEException, java.text.ParseException {
        var rpRequestedScopes = new Scope(OPENID, PHONE, ACCOUNT_MANAGEMENT);
        registerClient(rpRequestedScopes.toStringList(), false);

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(Optional.empty()),
                        constructQueryStringParameters(rpRequestedScopes.toString(), null),
                        Optional.of("GET"));

        var claimsRequest = getValidatedClaimsRequest(response);

        assertTrue(Objects.nonNull(claimsRequest.getUserInfoClaimsRequest().get("phone_number")));
        assertTrue(
                Objects.nonNull(
                        claimsRequest.getUserInfoClaimsRequest().get("phone_number_verified")));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        AUTHORISATION_REQUEST_RECEIVED,
                        AUTHORISATION_REQUEST_PARSED,
                        AUTHORISATION_INITIATED));
    }

    @Test
    void
            shouldSendSecureJarToAuthenticationWithRelevantScopesAndAddEmailClaimsWhenEmailScopeIsPresent()
                    throws ParseException, JOSEException, java.text.ParseException {
        var rpRequestedScopes = new Scope(OPENID, EMAIL, ACCOUNT_MANAGEMENT);
        registerClient(rpRequestedScopes.toStringList(), false);

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(Optional.empty()),
                        constructQueryStringParameters(rpRequestedScopes.toString(), null),
                        Optional.of("GET"));

        var claimsRequest = getValidatedClaimsRequest(response);

        assertTrue(Objects.nonNull(claimsRequest.getUserInfoClaimsRequest().get("email")));
        assertTrue(Objects.nonNull(claimsRequest.getUserInfoClaimsRequest().get("email_verified")));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        AUTHORISATION_REQUEST_RECEIVED,
                        AUTHORISATION_REQUEST_PARSED,
                        AUTHORISATION_INITIATED));
    }

    @Test
    void
            shouldSendSecureJarToAuthenticationWithRelevantScopesAndAddGovUkAccountClaimWhenGovUkScopeIsPresent()
                    throws ParseException, JOSEException, java.text.ParseException {
        var rpRequestedScopes = new Scope(OPENID, PHONE, EMAIL, GOVUK_ACCOUNT);
        registerClient(rpRequestedScopes.toStringList(), false);

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(Optional.empty()),
                        constructQueryStringParameters(rpRequestedScopes.toString(), null),
                        Optional.of("GET"));

        var claimsRequest = getValidatedClaimsRequest(response);

        var govUkAccountExpectedClaim =
                claimsRequest.getUserInfoClaimsRequest().get("legacy_subject_id");
        assertThat(Objects.nonNull(govUkAccountExpectedClaim), equalTo(true));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        AUTHORISATION_REQUEST_RECEIVED,
                        AUTHORISATION_REQUEST_PARSED,
                        AUTHORISATION_INITIATED));
    }

    private Map<String, String> constructQueryStringParameters(String scopes, String vtr) {
        final Map<String, String> queryStringParameters =
                new HashMap<>(
                        Map.of(
                                "response_type",
                                "code",
                                "redirect_uri",
                                RP_REDIRECT_URI,
                                "state",
                                "8VAVNSxHO1HwiNDhwchQKdd7eOUK3ltKfQzwPDxu9LU",
                                "nonce",
                                new Nonce().getValue(),
                                "client_id",
                                CLIENT_ID,
                                "scope",
                                scopes));

        Optional.ofNullable(vtr).ifPresent(s -> queryStringParameters.put("vtr", jsonArrayOf(vtr)));

        return queryStringParameters;
    }

    private AuthorizationRequest validateQueryRequestToAuthenticationAndReturnAuthRequest(
            APIGatewayProxyResponseEvent response) throws ParseException {
        assertThat(response, hasStatus(302));
        var redirectUri = getLocationResponseHeader(response);
        assertThat(
                redirectUri,
                startsWith(TEST_CONFIGURATION_SERVICE.getAuthFrontendBaseURL().toString()));
        var authorizationRequest = AuthorizationRequest.parse(URI.create(redirectUri));
        assertThat(authorizationRequest.getClientID().getValue(), equalTo(AUTH_INTERNAL_CLIENT_ID));
        assertThat(authorizationRequest.getResponseType(), equalTo(ResponseType.CODE));
        assertTrue(Objects.nonNull(authorizationRequest.getRequestObject()));
        return authorizationRequest;
    }

    private OIDCClaimsRequest getValidatedClaimsRequest(APIGatewayProxyResponseEvent response)
            throws ParseException, JOSEException, java.text.ParseException {
        var authorizationRequest =
                validateQueryRequestToAuthenticationAndReturnAuthRequest(response);
        var encryptedRequestObject = authorizationRequest.getRequestObject();
        var signedJWTResponse = decryptJWT((EncryptedJWT) encryptedRequestObject);
        validateStandardClaimsInJar(signedJWTResponse);
        assertThat(
                Objects.nonNull(signedJWTResponse.getJWTClaimsSet().getClaim("claim")),
                equalTo(true));

        return OIDCClaimsRequest.parse(
                (String) signedJWTResponse.getJWTClaimsSet().getClaim("claim"));
    }

    private void validateStandardClaimsInJar(SignedJWT signedJWT) throws java.text.ParseException {
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("jti")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("state")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("client_name")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("cookie_consent_shared")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("is_one_login_service")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("service_type")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("rp_client_id")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("rp_sector_host")));
        assertTrue(
                Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("govuk_signin_journey_id")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("state")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("client_id")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("redirect_uri")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("exp")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("iat")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("nbf")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("aud")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("iss")));
        assertThat(
                signedJWT.getJWTClaimsSet().getClaim("client_id"),
                equalTo(AUTH_INTERNAL_CLIENT_ID));
        assertThat(signedJWT.getJWTClaimsSet().getClaim("iss"), equalTo(AUTH_INTERNAL_CLIENT_ID));
        assertThat(signedJWT.getJWTClaimsSet().getClaim("client_name"), equalTo(CLIENT_NAME));
        assertThat(
                (boolean) signedJWT.getJWTClaimsSet().getClaim("is_one_login_service"),
                equalTo(false));
        assertThat(
                (boolean) signedJWT.getJWTClaimsSet().getClaim("cookie_consent_shared"),
                equalTo(false));
        assertThat(
                signedJWT.getJWTClaimsSet().getClaim("service_type"),
                equalTo(ServiceType.MANDATORY.toString()));
        assertThat(
                signedJWT.getJWTClaimsSet().getClaim("redirect_uri"),
                equalTo(ORCHESTRATION_REDIRECT_URI));
        assertThat(signedJWT.getJWTClaimsSet().getClaim("rp_client_id"), equalTo(CLIENT_ID));
        assertThat(
                signedJWT.getJWTClaimsSet().getClaim("rp_sector_host"),
                equalTo("rp-sector-uri.com"));
        assertThat(signedJWT.getHeader().getAlgorithm(), equalTo(ES256));
    }

    private String getLocationResponseHeader(APIGatewayProxyResponseEvent response) {
        return response.getHeaders().get(ResponseHeaders.LOCATION);
    }

    private void registerClient(List<String> scopes, boolean identitySupported) {
        clientStore.registerClient(
                CLIENT_ID,
                CLIENT_NAME,
                singletonList(RP_REDIRECT_URI),
                singletonList("joe.bloggs@digital.cabinet-office.gov.uk"),
                scopes,
                Base64.getMimeEncoder().encodeToString(KEY_PAIR.getPublic().getEncoded()),
                singletonList("https://localhost/post-redirect-logout"),
                "https://example.com",
                String.valueOf(ServiceType.MANDATORY),
                RP_SECTOR_URI,
                "public",
                ClientType.WEB,
                ES256.getName(),
                identitySupported);
    }

    private SignedJWT decryptJWT(EncryptedJWT encryptedJWT) throws JOSEException {
        encryptedJWT.decrypt(new RSADecrypter(KEY_PAIR.getPrivate()));
        return encryptedJWT.getPayload().toSignedJWT();
    }

    private static class TestConfigurationService extends IntegrationTestConfigurationService {

        public TestConfigurationService() {
            super(
                    externalTokenSigner,
                    storageTokenSigner,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters);
        }

        @Override
        public String getOrchestrationToAuthenticationTokenSigningKeyAlias() {
            return orchestrationPrivateKeyJwtSigner.getKeyAlias();
        }

        @Override
        public String getOrchestrationToAuthenticationEncryptionPublicKey() {
            return publicKey;
        }

        @Override
        public String getTxmaAuditQueueUrl() {
            return txmaAuditQueue.getQueueUrl();
        }

        @Override
        public String getOrchestrationClientId() {
            return AUTH_INTERNAL_CLIENT_ID;
        }

        @Override
        public String getOrchestrationRedirectURI() {
            return ORCHESTRATION_REDIRECT_URI;
        }

        @Override
        public boolean isIdentityEnabled() {
            return true;
        }
    }
}
