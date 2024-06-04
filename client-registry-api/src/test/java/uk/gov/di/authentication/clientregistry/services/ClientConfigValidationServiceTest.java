package uk.gov.di.authentication.clientregistry.services;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.client.RegistrationError;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.clientregistry.entity.ClientRegistrationRequest;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.UpdateClientConfigRequest;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.exceptions.ClientRegistrryConfigValidationException;

import java.util.List;
import java.util.stream.Stream;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_CLAIM;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_CLIENT_LOCS;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_CLIENT_TYPE;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_ID_TOKEN_SIGNING_ALGORITHM;
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
            String clientType)
            throws ClientRegistrryConfigValidationException {
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
                        clientType,
                        JWSAlgorithm.ES256.getName()));
    }

    @Test
    void shouldThrowExceptionForInvalidPostLogoutUriInRegistrationRequest() {
        var exception =
                assertThrows(
                        ClientRegistrryConfigValidationException.class,
                        () ->
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
                                                ClientType.WEB.getValue(),
                                                JWSAlgorithm.ES256.getName())));
        assertThat(exception.getErrorObject(), equalTo(INVALID_POST_LOGOUT_URI));
    }

    @Test
    void shouldThrowExceptionForInvalidRedirectUriInRegistrationequest() {
        var exception =
                assertThrows(
                        ClientRegistrryConfigValidationException.class,
                        () ->
                                validationService.validateClientRegistrationConfig(
                                        generateClientRegRequest(
                                                singletonList("invalid-redirect-uri"),
                                                VALID_PUBLIC_CERT,
                                                singletonList("openid"),
                                                singletonList(
                                                        "http://localhost/post-redirect-logout"),
                                                "http://example.com",
                                                String.valueOf(MANDATORY),
                                                "http://test.com",
                                                "public",
                                                emptyList(),
                                                ClientType.WEB.getValue(),
                                                JWSAlgorithm.ES256.getName())));
        assertThat(exception.getErrorObject(), equalTo(RegistrationError.INVALID_REDIRECT_URI));
    }

    @Test
    void shouldThrowExceptionForInvalidPublicKeyInRegistrationRequest() {
        var exception =
                assertThrows(
                        ClientRegistrryConfigValidationException.class,
                        () ->
                                validationService.validateClientRegistrationConfig(
                                        generateClientRegRequest(
                                                singletonList("http://localhost:1000/redirect"),
                                                "invalid-public-cert",
                                                singletonList("openid"),
                                                singletonList(
                                                        "http://localhost/post-redirect-logout"),
                                                "http://example.com",
                                                String.valueOf(MANDATORY),
                                                "http://test.com",
                                                "public",
                                                emptyList(),
                                                ClientType.WEB.getValue(),
                                                JWSAlgorithm.ES256.getName())));
        assertThat(exception.getErrorObject(), equalTo(INVALID_PUBLIC_KEY));
    }

    @Test
    void shouldThrowExceptionForInvalidScopesInRegistrationRequest() {
        var exception =
                assertThrows(
                        ClientRegistrryConfigValidationException.class,
                        () ->
                                validationService.validateClientRegistrationConfig(
                                        generateClientRegRequest(
                                                singletonList("http://localhost:1000/redirect"),
                                                VALID_PUBLIC_CERT,
                                                List.of("openid", "email", "fax"),
                                                singletonList(
                                                        "http://localhost/post-redirect-logout"),
                                                "http://example.com",
                                                String.valueOf(MANDATORY),
                                                "http://test.com",
                                                "public",
                                                emptyList(),
                                                ClientType.WEB.getValue(),
                                                JWSAlgorithm.ES256.getName())));
        assertThat(exception.getErrorObject(), equalTo(INVALID_SCOPE));
    }

    @Test
    void shouldThrowExceptionForPrivateScopeInRegistrationRequest() {
        var exception =
                assertThrows(
                        ClientRegistrryConfigValidationException.class,
                        () ->
                                validationService.validateClientRegistrationConfig(
                                        generateClientRegRequest(
                                                singletonList("http://localhost:1000/redirect"),
                                                VALID_PUBLIC_CERT,
                                                List.of("openid", "am"),
                                                singletonList(
                                                        "http://localhost/post-redirect-logout"),
                                                "http://example.com",
                                                String.valueOf(MANDATORY),
                                                "http://test.com",
                                                "public",
                                                emptyList(),
                                                ClientType.WEB.getValue(),
                                                JWSAlgorithm.ES256.getName())));
        assertThat(exception.getErrorObject(), equalTo(INVALID_SCOPE));
    }

    @Test
    void shouldThrowExceptionForInvalidClaimsInRegistrationRequest() {
        var exception =
                assertThrows(
                        ClientRegistrryConfigValidationException.class,
                        () ->
                                validationService.validateClientRegistrationConfig(
                                        generateClientRegRequest(
                                                singletonList("http://localhost:1000/redirect"),
                                                VALID_PUBLIC_CERT,
                                                singletonList("openid"),
                                                singletonList(
                                                        "http://localhost/post-redirect-logout"),
                                                "http://example.com",
                                                String.valueOf(MANDATORY),
                                                "http://test.com",
                                                "public",
                                                List.of("name", "email"),
                                                ClientType.WEB.getValue(),
                                                JWSAlgorithm.ES256.getName())));
        assertThat(exception.getErrorObject(), equalTo(INVALID_CLAIM));
    }

    @Test
    void shouldThrowExceptionForInvalidClientTypeInRegistrationRequest() {
        var exception =
                assertThrows(
                        ClientRegistrryConfigValidationException.class,
                        () ->
                                validationService.validateClientRegistrationConfig(
                                        generateClientRegRequest(
                                                singletonList("http://localhost:1000/redirect"),
                                                VALID_PUBLIC_CERT,
                                                singletonList("openid"),
                                                singletonList(
                                                        "http://localhost/post-redirect-logout"),
                                                "http://example.com",
                                                String.valueOf(MANDATORY),
                                                "http://test.com",
                                                "public",
                                                emptyList(),
                                                "Mobile",
                                                JWSAlgorithm.ES256.getName())));
        assertThat(exception.getErrorObject(), equalTo(INVALID_CLIENT_TYPE));
    }

    @Test
    void shouldThrowExceptionForInvalidClientLoCsInRegistrationRequest() {
        ClientRegistrationRequest regReq =
                new ClientRegistrationRequest(
                        "",
                        singletonList("http://localhost:1000/redirect"),
                        singletonList("test-client@test.com"),
                        VALID_PUBLIC_CERT,
                        singletonList("openid"),
                        singletonList("http://localhost/post-redirect-logout"),
                        "http://example.com",
                        String.valueOf(MANDATORY),
                        "http://test.com",
                        "public",
                        false,
                        emptyList(),
                        ClientType.WEB.getValue(),
                        JWSAlgorithm.ES256.getName(),
                        List.of("Unsupported_LoC"));

        var exception =
                assertThrows(
                        ClientRegistrryConfigValidationException.class,
                        () -> validationService.validateClientRegistrationConfig(regReq));
        assertThat(exception.getErrorObject(), equalTo(INVALID_CLIENT_LOCS));
    }

    @ParameterizedTest
    @MethodSource("invalidAlgorithmSource")
    void shouldThrowExceptionForInvalidIdTokenSigningAlgorithmInInRegistrationRequest(
            String invalidIdTokenSource) {
        ClientRegistrationRequest regReq =
                new ClientRegistrationRequest(
                        "",
                        singletonList("http://localhost:1000/redirect"),
                        singletonList("test-client@test.com"),
                        VALID_PUBLIC_CERT,
                        singletonList("openid"),
                        singletonList("http://localhost/post-redirect-logout"),
                        "http://example.com",
                        String.valueOf(MANDATORY),
                        "http://test.com",
                        "public",
                        false,
                        emptyList(),
                        ClientType.WEB.getValue(),
                        invalidIdTokenSource,
                        List.of("Unsupported_LoC"));

        var exception =
                assertThrows(
                        ClientRegistrryConfigValidationException.class,
                        () -> validationService.validateClientRegistrationConfig(regReq));
        assertThat(exception.getErrorObject(), equalTo(INVALID_ID_TOKEN_SIGNING_ALGORITHM));
    }

    @ParameterizedTest
    @MethodSource("subjectTypes")
    void shouldCorrectlyValidateSubjectTypeInRegistrationRequest(
            String subjectType, boolean isValid) throws Throwable {

        Executable exec =
                () ->
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
                                        ClientType.WEB.getValue(),
                                        JWSAlgorithm.ES256.getName()));

        if (isValid) {
            exec.execute();
        } else {
            var exception = assertThrows(ClientRegistrryConfigValidationException.class, exec);
            assertThat(exception.getErrorObject(), equalTo(INVALID_SUBJECT_TYPE));
        }
    }

    private static Stream<Arguments> subjectTypes() {
        return Stream.of(
                Arguments.of("public", true),
                Arguments.of("pairwise", true),
                Arguments.of("PUBLIC", false),
                Arguments.of("PAIRWISE", false));
    }

    @Test
    void shouldPassValidationForValidUpdateRequest()
            throws ClientRegistrryConfigValidationException {
        validationService.validateClientConfig(
                generateClientUpdateRequest(
                        singletonList("http://localhost:1000/redirect"),
                        VALID_PUBLIC_CERT,
                        singletonList("openid"),
                        singletonList("http://localhost/post-redirect-logout"),
                        String.valueOf(MANDATORY),
                        false,
                        "http://localhost/sector-id",
                        ClientType.WEB.getValue(),
                        JWSAlgorithm.ES256.getName(),
                        List.of(LevelOfConfidence.MEDIUM_LEVEL.getValue())));
    }

    @Test
    void shouldPassValidationForEmptyUpdateRequest()
            throws ClientRegistrryConfigValidationException {
        validationService.validateClientConfig(new UpdateClientConfigRequest());
    }

    @Test
    void shouldThrowExceptionForInvalidPostLogoutUriInUpdateRequest() {
        var exception =
                assertThrows(
                        ClientRegistrryConfigValidationException.class,
                        () ->
                                validationService.validateClientConfig(
                                        generateClientUpdateRequest(
                                                singletonList("http://localhost:1000/redirect"),
                                                VALID_PUBLIC_CERT,
                                                singletonList("openid"),
                                                singletonList("invalid-logout-uri"),
                                                String.valueOf(MANDATORY),
                                                false,
                                                null,
                                                ClientType.WEB.getValue(),
                                                JWSAlgorithm.ES256.getName(),
                                                List.of(
                                                        LevelOfConfidence.MEDIUM_LEVEL
                                                                .getValue()))));
        assertThat(exception.getErrorObject(), equalTo(INVALID_POST_LOGOUT_URI));
    }

    @Test
    void shouldReturnErrorForInvalidRedirectUriInUpdateRequest() {
        var exception =
                assertThrows(
                        ClientRegistrryConfigValidationException.class,
                        () ->
                                validationService.validateClientConfig(
                                        generateClientUpdateRequest(
                                                singletonList("invalid-redirect-uri"),
                                                VALID_PUBLIC_CERT,
                                                singletonList("openid"),
                                                singletonList(
                                                        "http://localhost/post-redirect-logout"),
                                                String.valueOf(MANDATORY),
                                                false,
                                                null,
                                                ClientType.WEB.getValue(),
                                                JWSAlgorithm.ES256.getName(),
                                                List.of(
                                                        LevelOfConfidence.MEDIUM_LEVEL
                                                                .getValue()))));
        assertThat(exception.getErrorObject(), equalTo(RegistrationError.INVALID_REDIRECT_URI));
    }

    @Test
    void shouldReturnErrorForInvalidPublicKeyInUpdateRequest() {
        var exception =
                assertThrows(
                        ClientRegistrryConfigValidationException.class,
                        () ->
                                validationService.validateClientConfig(
                                        generateClientUpdateRequest(
                                                singletonList("http://localhost:1000/redirect"),
                                                "invalid-public-cert",
                                                singletonList("openid"),
                                                singletonList(
                                                        "http://localhost/post-redirect-logout"),
                                                String.valueOf(MANDATORY),
                                                false,
                                                null,
                                                JWSAlgorithm.ES256.getName(),
                                                ClientType.WEB.getValue(),
                                                List.of(
                                                        LevelOfConfidence.MEDIUM_LEVEL
                                                                .getValue()))));
        assertThat(exception.getErrorObject(), equalTo(INVALID_PUBLIC_KEY));
    }

    @Test
    void shouldReturnErrorForInvalidScopesInUpdateRequest() {
        var exception =
                assertThrows(
                        ClientRegistrryConfigValidationException.class,
                        () ->
                                validationService.validateClientConfig(
                                        generateClientUpdateRequest(
                                                singletonList("http://localhost:1000/redirect"),
                                                VALID_PUBLIC_CERT,
                                                List.of("openid", "email", "fax"),
                                                singletonList(
                                                        "http://localhost/post-redirect-logout"),
                                                String.valueOf(MANDATORY),
                                                false,
                                                null,
                                                ClientType.WEB.getValue(),
                                                JWSAlgorithm.ES256.getName(),
                                                List.of(
                                                        LevelOfConfidence.MEDIUM_LEVEL
                                                                .getValue()))));
        assertThat(exception.getErrorObject(), equalTo(INVALID_SCOPE));
    }

    @Test
    void shouldReturnErrorForInvalidClientTypeInUpdateRequest() {
        var exception =
                assertThrows(
                        ClientRegistrryConfigValidationException.class,
                        () ->
                                validationService.validateClientConfig(
                                        generateClientUpdateRequest(
                                                singletonList("http://localhost:1000/redirect"),
                                                VALID_PUBLIC_CERT,
                                                List.of("openid", "email"),
                                                singletonList(
                                                        "http://localhost/post-redirect-logout"),
                                                String.valueOf(MANDATORY),
                                                false,
                                                null,
                                                JWSAlgorithm.ES256.getName(),
                                                "rubbish-client-type",
                                                List.of(
                                                        LevelOfConfidence.MEDIUM_LEVEL
                                                                .getValue()))));
        assertThat(exception.getErrorObject(), equalTo(INVALID_CLIENT_TYPE));
    }

    @Test
    void shouldReturnErrorForInvalidClientLoCsInUpdateRequest() {
        var exception =
                assertThrows(
                        ClientRegistrryConfigValidationException.class,
                        () ->
                                validationService.validateClientConfig(
                                        generateClientUpdateRequest(
                                                singletonList("http://localhost:1000/redirect"),
                                                VALID_PUBLIC_CERT,
                                                List.of("openid", "email", "fax"),
                                                singletonList(
                                                        "http://localhost/post-redirect-logout"),
                                                String.valueOf(MANDATORY),
                                                false,
                                                null,
                                                ClientType.WEB.getValue(),
                                                JWSAlgorithm.ES256.getName(),
                                                List.of("Unsupported_LoC"))));
        assertThat(exception.getErrorObject(), equalTo(INVALID_CLIENT_LOCS));
    }

    @ParameterizedTest
    @MethodSource("invalidAlgorithmSource")
    void shouldReturnErrorForInvalidIdTokenSigningAlgorithmInUpdateRequest(
            String invalidIdTokenSource) {
        var exception =
                assertThrows(
                        ClientRegistrryConfigValidationException.class,
                        () ->
                                validationService.validateClientConfig(
                                        generateClientUpdateRequest(
                                                singletonList("http://localhost:1000/redirect"),
                                                VALID_PUBLIC_CERT,
                                                List.of("openid", "email", "fax"),
                                                singletonList(
                                                        "http://localhost/post-redirect-logout"),
                                                String.valueOf(MANDATORY),
                                                false,
                                                null,
                                                ClientType.WEB.getValue(),
                                                invalidIdTokenSource,
                                                List.of(
                                                        LevelOfConfidence.MEDIUM_LEVEL
                                                                .getValue()))));
        assertThat(exception.getErrorObject(), equalTo(INVALID_ID_TOKEN_SIGNING_ALGORITHM));
    }

    static Stream<Arguments> invalidAlgorithmSource() {
        return Stream.of(Arguments.of("NOT_AN_ALGORITHM", JWSAlgorithm.PS256.getName()));
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
            String clientType,
            String idTokenSigningAlgorithm) {
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
                clientType,
                idTokenSigningAlgorithm);
    }

    private UpdateClientConfigRequest generateClientUpdateRequest(
            List<String> redirectUri,
            String publicCert,
            List<String> scopes,
            List<String> postLogoutUris,
            String serviceType,
            boolean jarValidationRequired,
            String sectorURI,
            String clientType,
            String idTokenSigningAlgorithm,
            List<String> clientLoCs) {
        UpdateClientConfigRequest configRequest = new UpdateClientConfigRequest();
        configRequest.setScopes(scopes);
        configRequest.setRedirectUris(redirectUri);
        configRequest.setPublicKey(publicCert);
        configRequest.setPostLogoutRedirectUris(postLogoutUris);
        configRequest.setServiceType(serviceType);
        configRequest.setJarValidationRequired(jarValidationRequired);
        configRequest.setSectorIdentifierUri(sectorURI);
        configRequest.setClientType(clientType);
        configRequest.setIdTokenSigningAlgorithm(idTokenSigningAlgorithm);
        configRequest.setClientLoCs(clientLoCs);
        return configRequest;
    }
}
