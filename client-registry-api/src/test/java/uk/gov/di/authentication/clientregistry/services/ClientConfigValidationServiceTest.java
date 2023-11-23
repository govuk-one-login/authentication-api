package uk.gov.di.authentication.clientregistry.services;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.client.RegistrationError;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.clientregistry.entity.ClientRegistrationRequest;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.UpdateClientConfigRequest;
import uk.gov.di.orchestration.shared.entity.ValidClaims;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_CLAIM;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_CLIENT_TYPE;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_POST_LOGOUT_URI;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_PUBLIC_KEY;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_SCOPE;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_SUBJECT_TYPE;
import static uk.gov.di.orchestration.shared.entity.ServiceType.MANDATORY;
import static uk.gov.di.orchestration.shared.entity.ServiceType.OPTIONAL;

class ClientConfigValidationServiceTest {

    private final ClientConfigValidationService validationService =
            new ClientConfigValidationService();
    private static final String VALID_PUBLIC_CERT =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxt91w8GsMDdklOpS8ZXAsIM1ztQZd5QT/bRCQahZJeS1a6Os4hbuKwzHlz52zfTNp7BL4RB/KOcRIPhOQLgqeyM+bVngRa1EIfTkugJHS2/gu2Xv0aelwvXj8FZgAPRPD+ps2wiV4tUehrFIsRyHZM3yOp9g6qapCcxF7l0E1PlVkKPcPNmxn2oFiqnP6ZThGbE+N2avdXHcySIqt/v6Hbmk8cDHzSExazW7j/XvA+xnp0nQ5m2GisCZul5If5edCTXD0tKzx/I/gtEG4gkv9kENWOt4grP8/0zjNAl2ac6kpRny3tY5RkKBKCOB1VHwq2lUTSNKs32O1BsA5ByyYQIDAQAB";

    private static Stream<Arguments> registrationRequestParams() {
        return Stream.of(
                Arguments.of(emptyList(), null, emptyList(), null, null),
                Arguments.of(null, null, null, null, null, null),
                Arguments.of(
                        singletonList("http://localhost/post-redirect-logout"),
                        "http://back-channel.com",
                        List.of(ValidClaims.ADDRESS.getValue()),
                        String.valueOf(MANDATORY),
                        ClientType.WEB.getValue()),
                Arguments.of(
                        List.of(
                                "http://localhost/post-redirect-logout",
                                "http://localhost/post-redirect-logout-v2"),
                        "http://back-channel.com",
                        List.of(
                                ValidClaims.CORE_IDENTITY_JWT.getValue(),
                                ValidClaims.ADDRESS.getValue(),
                                ValidClaims.PASSPORT.getValue()),
                        String.valueOf(OPTIONAL),
                        ClientType.APP.getValue()));
    }

    @ParameterizedTest
    @MethodSource("registrationRequestParams")
    void shouldPassValidationForValidRegistrationRequest(
            List<String> postlogoutUris,
            String backChannelLogoutUri,
            List<String> claims,
            String serviceType,
            String clientType) {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                VALID_PUBLIC_CERT,
                                singletonList("openid"),
                                postlogoutUris,
                                backChannelLogoutUri,
                                serviceType,
                                "http://test.com",
                                "public",
                                claims,
                                clientType));
        assertThat(errorResponse, equalTo(Optional.empty()));
    }

    @Test
    void shouldReturnErrorForInvalidPostLogoutUriInRegistrationRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                VALID_PUBLIC_CERT,
                                singletonList("openid"),
                                singletonList("invalid-logout-uri"),
                                "http://example.com",
                                String.valueOf(MANDATORY),
                                "http://test.com",
                                "public",
                                emptyList(),
                                ClientType.WEB.getValue()));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_POST_LOGOUT_URI)));
    }

    @Test
    void shouldReturnErrorForInvalidRedirectUriInRegistrationequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("invalid-redirect-uri"),
                                VALID_PUBLIC_CERT,
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                "http://example.com",
                                String.valueOf(MANDATORY),
                                "http://test.com",
                                "public",
                                emptyList(),
                                ClientType.WEB.getValue()));
        assertThat(errorResponse, equalTo(Optional.of(RegistrationError.INVALID_REDIRECT_URI)));
    }

    @Test
    void shouldReturnErrorForInvalidPublicKeyInRegistrationRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                "invalid-public-cert",
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                "http://example.com",
                                String.valueOf(MANDATORY),
                                "http://test.com",
                                "public",
                                emptyList(),
                                ClientType.WEB.getValue()));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_PUBLIC_KEY)));
    }

    @Test
    void shouldReturnErrorForInvalidScopesInRegistrationRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                VALID_PUBLIC_CERT,
                                List.of("openid", "email", "fax"),
                                singletonList("http://localhost/post-redirect-logout"),
                                "http://example.com",
                                String.valueOf(MANDATORY),
                                "http://test.com",
                                "public",
                                emptyList(),
                                ClientType.WEB.getValue()));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_SCOPE)));
    }

    @Test
    void shouldReturnErrorForPrivateScopeInRegistrationRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                VALID_PUBLIC_CERT,
                                List.of("openid", "am"),
                                singletonList("http://localhost/post-redirect-logout"),
                                "http://example.com",
                                String.valueOf(MANDATORY),
                                "http://test.com",
                                "public",
                                emptyList(),
                                ClientType.WEB.getValue()));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_SCOPE)));
    }

    @Test
    void shouldReturnErrorForInvalidClaimsInRegistrationRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                VALID_PUBLIC_CERT,
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                "http://example.com",
                                String.valueOf(MANDATORY),
                                "http://test.com",
                                "public",
                                List.of("name", "email"),
                                ClientType.WEB.getValue()));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_CLAIM)));
    }

    @Test
    void shouldReturnErrorForInvalidClientTypeInRegistrationRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                VALID_PUBLIC_CERT,
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                "http://example.com",
                                String.valueOf(MANDATORY),
                                "http://test.com",
                                "public",
                                emptyList(),
                                "Mobile"));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_CLIENT_TYPE)));
    }

    @ParameterizedTest
    @MethodSource("subjectTypes")
    void shouldCorrectlyValidateSubjectTypeInRegistrationRequest(
            String subjectType, Optional<ErrorObject> expectedResult) {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                VALID_PUBLIC_CERT,
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                "http://example.com",
                                String.valueOf(MANDATORY),
                                "http://test.com",
                                subjectType,
                                emptyList(),
                                ClientType.WEB.getValue()));
        assertThat(errorResponse, equalTo(expectedResult));
    }

    private static Stream<Arguments> subjectTypes() {
        return Stream.of(
                Arguments.of("public", Optional.empty()),
                Arguments.of("pairwise", Optional.empty()),
                Arguments.of("PUBLIC", Optional.of(INVALID_SUBJECT_TYPE)),
                Arguments.of("PAIRWISE", Optional.of(INVALID_SUBJECT_TYPE)));
    }

    @Test
    void shouldPassValidationForValidUpdateRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientUpdateConfig(
                        generateClientUpdateRequest(
                                singletonList("http://localhost:1000/redirect"),
                                VALID_PUBLIC_CERT,
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                String.valueOf(MANDATORY),
                                "http://localhost/sector-id",
                                ClientType.WEB.getValue()));
        assertThat(errorResponse, equalTo(Optional.empty()));
    }

    @Test
    void shouldReturnOptionalEmptyForEmptyUpdateRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientUpdateConfig(new UpdateClientConfigRequest());
        assertThat(errorResponse, equalTo(Optional.empty()));
    }

    @Test
    void shouldReturnErrorForInvalidPostLogoutUriInUpdateRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientUpdateConfig(
                        generateClientUpdateRequest(
                                singletonList("http://localhost:1000/redirect"),
                                VALID_PUBLIC_CERT,
                                singletonList("openid"),
                                singletonList("invalid-logout-uri"),
                                String.valueOf(MANDATORY),
                                null,
                                ClientType.WEB.getValue()));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_POST_LOGOUT_URI)));
    }

    @Test
    void shouldReturnErrorForInvalidRedirectUriInUpdateRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientUpdateConfig(
                        generateClientUpdateRequest(
                                singletonList("invalid-redirect-uri"),
                                VALID_PUBLIC_CERT,
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                String.valueOf(MANDATORY),
                                null,
                                ClientType.WEB.getValue()));
        assertThat(errorResponse, equalTo(Optional.of(RegistrationError.INVALID_REDIRECT_URI)));
    }

    @Test
    void shouldReturnErrorForInvalidPublicKeyInUpdateRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientUpdateConfig(
                        generateClientUpdateRequest(
                                singletonList("http://localhost:1000/redirect"),
                                "invalid-public-cert",
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                String.valueOf(MANDATORY),
                                null,
                                ClientType.WEB.getValue()));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_PUBLIC_KEY)));
    }

    @Test
    void shouldReturnErrorForInvalidScopesInUpdateRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientUpdateConfig(
                        generateClientUpdateRequest(
                                singletonList("http://localhost:1000/redirect"),
                                VALID_PUBLIC_CERT,
                                List.of("openid", "email", "fax"),
                                singletonList("http://localhost/post-redirect-logout"),
                                String.valueOf(MANDATORY),
                                null,
                                ClientType.WEB.getValue()));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_SCOPE)));
    }

    @Test
    void shouldReturnErrorForInvalidClientTypeInUpdateRequest() {
        var errorResponse =
                validationService.validateClientUpdateConfig(
                        generateClientUpdateRequest(
                                singletonList("http://localhost:1000/redirect"),
                                VALID_PUBLIC_CERT,
                                List.of("openid", "email"),
                                singletonList("http://localhost/post-redirect-logout"),
                                String.valueOf(MANDATORY),
                                null,
                                "rubbish-client-type"));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_CLIENT_TYPE)));
    }

    private ClientRegistrationRequest generateClientRegRequest(
            List<String> redirectUri,
            String publicCert,
            List<String> scopes,
            List<String> postLogoutUris,
            String backChannelLogoutUri,
            String serviceType,
            String sectorIdentifierUri,
            String subjectType,
            List<String> claims,
            String clientType) {
        return new ClientRegistrationRequest(
                "The test client",
                redirectUri,
                singletonList("test-client@test.com"),
                publicCert,
                scopes,
                postLogoutUris,
                backChannelLogoutUri,
                serviceType,
                sectorIdentifierUri,
                subjectType,
                false,
                claims,
                clientType);
    }

    private UpdateClientConfigRequest generateClientUpdateRequest(
            List<String> redirectUri,
            String publicCert,
            List<String> scopes,
            List<String> postLogoutUris,
            String serviceType,
            String sectorURI,
            String clientType) {
        UpdateClientConfigRequest configRequest = new UpdateClientConfigRequest();
        configRequest.setScopes(scopes);
        configRequest.setRedirectUris(redirectUri);
        configRequest.setPublicKey(publicCert);
        configRequest.setPostLogoutRedirectUris(postLogoutUris);
        configRequest.setServiceType(serviceType);
        configRequest.setSectorIdentifierUri(sectorURI);
        configRequest.setClientType(clientType);
        return configRequest;
    }
}
