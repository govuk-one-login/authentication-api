package uk.gov.di.authentication.api;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
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
import uk.gov.di.authentication.oidc.lambda.AuthorisationHandler;
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.helpers.LocaleHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.helper.KeyPairHelper;

import java.net.URI;
import java.security.KeyPair;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static com.nimbusds.openid.connect.sdk.OIDCScopeValue.EMAIL;
import static com.nimbusds.openid.connect.sdk.OIDCScopeValue.OFFLINE_ACCESS;
import static com.nimbusds.openid.connect.sdk.OIDCScopeValue.OPENID;
import static com.nimbusds.openid.connect.sdk.OIDCScopeValue.PHONE;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.oidc.domain.OidcAuditableEvent.AUTHORISATION_INITIATED;
import static uk.gov.di.authentication.oidc.domain.OidcAuditableEvent.AUTHORISATION_REQUEST_RECEIVED;
import static uk.gov.di.authentication.shared.entity.CustomScopeValue.ACCOUNT_MANAGEMENT;
import static uk.gov.di.authentication.shared.entity.CustomScopeValue.GOVUK_ACCOUNT;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper.jsonArrayOf;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class OrchestrationToAuthenticationAuthorizeIntegrationTest
        extends ApiGatewayHandlerIntegrationTest {

    private static final String CLIENT_ID = "gfdsfdsf7s323hfsd";
    private static final String CLIENT_NAME = "test-client";
    private static final String AUTH_INTERNAL_CLIENT_ID = "authentication-orch-client-id";
    private static final String RP_REDIRECT_URI = "https://rp-uri/redirect";
    private static final String ORCHESTRATION_REDIRECT_URI = "https://orchestration/redirect";
    private static final KeyPair KEY_PAIR = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
    private final String publicKey =
            "-----BEGIN PUBLIC KEY-----\n"
                    + Base64.getMimeEncoder().encodeToString(KEY_PAIR.getPublic().getEncoded())
                    + "\n-----END PUBLIC KEY-----\n";

    private final ConfigurationService configurationService =
            new OrchestrationToAuthenticationAuthorizeIntegrationTest.TestConfigurationService(
                    true);

    @BeforeEach
    void setup() {
        handler = new AuthorisationHandler(configurationService);
        txmaAuditQueue.clear();
    }

    @Test
    void shouldSendSecureJarToAuthenticationWithRelevantScopes()
            throws ParseException, JOSEException, java.text.ParseException {
        var rpRequestedScopes = new Scope(OPENID, PHONE, EMAIL);
        registerClient(rpRequestedScopes.toStringList(), false);

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(Optional.empty()),
                        constructQueryStringParameters(rpRequestedScopes.toString(), null));

        var authorizationRequest =
                validateQueryRequestToAuthenticationAndReturnAuthRequest(response);
        assertTrue(Objects.nonNull(authorizationRequest.getRequestObject()));
        var encryptedRequestObject = authorizationRequest.getRequestObject();
        var signedJWTResponse = decryptJWT((EncryptedJWT) encryptedRequestObject);
        validateStandardClaimsInJar(signedJWTResponse);
        assertThat(signedJWTResponse.getJWTClaimsSet().getClaim("claim"), equalTo(null));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldSendSecureJarToAuthenticationWithRelevantScopesAndOmitOfflineAccess()
            throws ParseException, JOSEException, java.text.ParseException {
        var rpRequestedScopes = new Scope(OPENID, PHONE, EMAIL, OFFLINE_ACCESS);
        registerClient(rpRequestedScopes.toStringList(), false);

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(Optional.empty()),
                        constructQueryStringParameters(rpRequestedScopes.toString(), null));

        var authorizationRequest =
                validateQueryRequestToAuthenticationAndReturnAuthRequest(response);
        var encryptedRequestObject = authorizationRequest.getRequestObject();
        var signedJWTResponse = decryptJWT((EncryptedJWT) encryptedRequestObject);
        validateStandardClaimsInJar(signedJWTResponse);
        assertThat(signedJWTResponse.getJWTClaimsSet().getClaim("claim"), equalTo(null));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
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
                        constructQueryStringParameters(rpRequestedScopes.toString(), "P2.Cl.Cm"));

        var authorizationRequest =
                validateQueryRequestToAuthenticationAndReturnAuthRequest(response);
        var encryptedRequestObject = authorizationRequest.getRequestObject();
        var signedJWTResponse = decryptJWT((EncryptedJWT) encryptedRequestObject);
        validateStandardClaimsInJar(signedJWTResponse);
        assertThat(
                Objects.nonNull(signedJWTResponse.getJWTClaimsSet().getClaim("claim")),
                equalTo(true));

        var claimsRequest =
                OIDCClaimsRequest.parse(
                        (String) signedJWTResponse.getJWTClaimsSet().getClaim("claim"));

        var identityExpectedSaltClaim = claimsRequest.getUserInfoClaimsRequest().get("salt");
        var identityExpectedLocalAccountIdClaim =
                claimsRequest.getUserInfoClaimsRequest().get("local_account_id");
        assertThat(Objects.nonNull(identityExpectedSaltClaim), equalTo(true));
        assertThat(Objects.nonNull(identityExpectedLocalAccountIdClaim), equalTo(true));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void
            shouldSendSecureJarToAuthenticationWithRelevantScopesAndAddAccountManagementClaimWhenAmScopeIsPresent()
                    throws ParseException, JOSEException, java.text.ParseException {
        var rpRequestedScopes = new Scope(OPENID, PHONE, EMAIL, ACCOUNT_MANAGEMENT);
        registerClient(rpRequestedScopes.toStringList(), false);

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(Optional.empty()),
                        constructQueryStringParameters(rpRequestedScopes.toString(), null));

        var authorizationRequest =
                validateQueryRequestToAuthenticationAndReturnAuthRequest(response);
        var encryptedRequestObject = authorizationRequest.getRequestObject();
        var signedJWTResponse = decryptJWT((EncryptedJWT) encryptedRequestObject);
        validateStandardClaimsInJar(signedJWTResponse);

        assertThat(
                Objects.nonNull(signedJWTResponse.getJWTClaimsSet().getClaim("claim")),
                equalTo(true));
        var claimsRequest =
                OIDCClaimsRequest.parse(
                        (String) signedJWTResponse.getJWTClaimsSet().getClaim("claim"));

        var accountManagementExpectedClaim =
                claimsRequest.getUserInfoClaimsRequest().get("public_subject_id");
        assertThat(Objects.nonNull(accountManagementExpectedClaim), equalTo(true));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
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
                        constructQueryStringParameters(rpRequestedScopes.toString(), null));

        var authorizationRequest =
                validateQueryRequestToAuthenticationAndReturnAuthRequest(response);
        var encryptedRequestObject = authorizationRequest.getRequestObject();
        var signedJWTResponse = decryptJWT((EncryptedJWT) encryptedRequestObject);

        validateStandardClaimsInJar(signedJWTResponse);
        assertThat(
                Objects.nonNull(signedJWTResponse.getJWTClaimsSet().getClaim("claim")),
                equalTo(true));
        var claimsRequest =
                OIDCClaimsRequest.parse(
                        (String) signedJWTResponse.getJWTClaimsSet().getClaim("claim"));

        var govUkAccountExpectedClaim =
                claimsRequest.getUserInfoClaimsRequest().get("legacy_subject_id");
        assertThat(Objects.nonNull(govUkAccountExpectedClaim), equalTo(true));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
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
        assertThat(redirectUri, startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));
        var authorizationRequest = AuthorizationRequest.parse(URI.create(redirectUri));
        assertThat(authorizationRequest.getClientID().getValue(), equalTo(AUTH_INTERNAL_CLIENT_ID));
        assertThat(authorizationRequest.getResponseType(), equalTo(ResponseType.CODE));
        assertTrue(Objects.nonNull(authorizationRequest.getRequestObject()));
        return authorizationRequest;
    }

    private void validateStandardClaimsInJar(SignedJWT signedJWT) throws java.text.ParseException {
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("jti")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("state")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("client_name")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("cookie_consent_shared")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("consent_required")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("is_one_login_service")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("service_type")));
        assertTrue(
                Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("govuk_signin_journey_id")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("confidence")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("state")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("client_id")));
        assertTrue(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim("scope")));
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
                (boolean) signedJWT.getJWTClaimsSet().getClaim("consent_required"), equalTo(false));
        assertThat(
                signedJWT.getJWTClaimsSet().getClaim("service_type"),
                equalTo(ServiceType.MANDATORY.toString()));
        assertThat(
                signedJWT.getJWTClaimsSet().getClaim("redirect_uri"),
                equalTo(ORCHESTRATION_REDIRECT_URI));
        assertThat(signedJWT.getHeader().getAlgorithm(), equalTo(JWSAlgorithm.ES256));
        var scope = Scope.parse((String) signedJWT.getJWTClaimsSet().getClaim("scope"));
        var expectedSentScopes = new Scope(OPENID, EMAIL, PHONE);
        assertThat(scope.size(), equalTo(expectedSentScopes.size()));
        assertThat(expectedSentScopes.containsAll(scope), equalTo(true));
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
                "https://test.com",
                "public",
                false,
                ClientType.WEB,
                identitySupported);
    }

    private SignedJWT decryptJWT(EncryptedJWT encryptedJWT) throws JOSEException {
        encryptedJWT.decrypt(new RSADecrypter(KEY_PAIR.getPrivate()));
        return encryptedJWT.getPayload().toSignedJWT();
    }

    private class TestConfigurationService extends IntegrationTestConfigurationService {

        private final boolean authOrchSplitEnabled;

        public TestConfigurationService(boolean authOrchSplitEnabled) {
            super(
                    auditTopic,
                    notificationsQueue,
                    auditSigningKey,
                    tokenSigner,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters);
            this.authOrchSplitEnabled = authOrchSplitEnabled;
        }

        @Override
        public boolean isAuthOrchSplitEnabled() {
            return authOrchSplitEnabled;
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
        public boolean isLanguageEnabled(LocaleHelper.SupportedLanguage supportedLanguage) {
            return supportedLanguage.equals(LocaleHelper.SupportedLanguage.EN)
                    || supportedLanguage.equals(LocaleHelper.SupportedLanguage.CY);
        }

        @Override
        public String getOrchestrationClientId() {
            return AUTH_INTERNAL_CLIENT_ID;
        }

        @Override
        public String getOrchestrationRedirectUri() {
            return ORCHESTRATION_REDIRECT_URI;
        }

        @Override
        public boolean isIdentityEnabled() {
            return true;
        }
    }
}
