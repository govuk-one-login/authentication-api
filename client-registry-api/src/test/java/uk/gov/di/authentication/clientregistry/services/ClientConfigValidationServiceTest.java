package uk.gov.di.authentication.clientregistry.services;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.client.RegistrationError;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.clientregistry.entity.ClientRegistrationRequest;
import uk.gov.di.orchestration.shared.entity.Channel;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.PublicKeySource;
import uk.gov.di.orchestration.shared.entity.UpdateClientConfigRequest;
import uk.gov.di.orchestration.shared.entity.ValidClaims;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_CLAIM;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_CLIENT_LOCS;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_CLIENT_TYPE;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_ID_TOKEN_SIGNING_ALGORITHM;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_JWKS_URI;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_LANDING_PAGE_URL;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_POST_LOGOUT_URI;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_PUBLIC_KEY;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_PUBLIC_KEY_SOURCE;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_SCOPE;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_SUBJECT_TYPE;
import static uk.gov.di.orchestration.shared.entity.ServiceType.MANDATORY;
import static uk.gov.di.orchestration.shared.entity.ServiceType.OPTIONAL;

class ClientConfigValidationServiceTest {

    private final ClientConfigValidationService validationService =
            new ClientConfigValidationService();
    private static final String VALID_PUBLIC_KEY =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxt91w8GsMDdklOpS8ZXAsIM1ztQZd5QT/bRCQahZJeS1a6Os4hbuKwzHlz52zfTNp7BL4RB/KOcRIPhOQLgqeyM+bVngRa1EIfTkugJHS2/gu2Xv0aelwvXj8FZgAPRPD+ps2wiV4tUehrFIsRyHZM3yOp9g6qapCcxF7l0E1PlVkKPcPNmxn2oFiqnP6ZThGbE+N2avdXHcySIqt/v6Hbmk8cDHzSExazW7j/XvA+xnp0nQ5m2GisCZul5If5edCTXD0tKzx/I/gtEG4gkv9kENWOt4grP8/0zjNAl2ac6kpRny3tY5RkKBKCOB1VHwq2lUTSNKs32O1BsA5ByyYQIDAQAB";

    private static final boolean IDENTITY_VERIFICATION_SUPPORTED = false;

    private static Stream<Arguments> registrationRequestParams() {
        return Stream.of(
                Arguments.of(
                        emptyList(),
                        null,
                        PublicKeySource.STATIC.getValue(),
                        VALID_PUBLIC_KEY,
                        null,
                        emptyList(),
                        null,
                        null,
                        null,
                        Channel.WEB.getValue(),
                        null),
                Arguments.of(
                        null,
                        null,
                        PublicKeySource.JWKS.getValue(),
                        null,
                        "https://valid.jwks.url.gov.uk",
                        null,
                        null,
                        null,
                        null,
                        Channel.STRATEGIC_APP.getValue(),
                        null),
                Arguments.of(
                        null,
                        null,
                        PublicKeySource.JWKS.getValue(),
                        null,
                        "https://valid.jwks.url.gov.uk",
                        null,
                        null,
                        null,
                        null,
                        Channel.GENERIC_APP.getValue(),
                        null),
                Arguments.of(
                        singletonList("http://localhost/post-redirect-logout"),
                        "http://back-channel.com",
                        PublicKeySource.STATIC.getValue(),
                        VALID_PUBLIC_KEY,
                        null,
                        List.of(ValidClaims.ADDRESS.getValue()),
                        String.valueOf(MANDATORY),
                        ClientType.WEB.getValue(),
                        ES256.getName(),
                        null,
                        null),
                Arguments.of(
                        List.of(
                                "http://localhost/post-redirect-logout",
                                "http://localhost/post-redirect-logout-v2"),
                        "http://back-channel.com",
                        null,
                        VALID_PUBLIC_KEY,
                        null,
                        List.of(
                                ValidClaims.CORE_IDENTITY_JWT.getValue(),
                                ValidClaims.ADDRESS.getValue(),
                                ValidClaims.PASSPORT.getValue()),
                        String.valueOf(OPTIONAL),
                        ClientType.APP.getValue(),
                        RS256.getName(),
                        Channel.WEB.getValue(),
                        "http://landing-page.com"));
    }

    @ParameterizedTest
    @MethodSource("registrationRequestParams")
    void shouldPassValidationForValidRegistrationRequest(
            List<String> postlogoutUris,
            String backChannelLogoutUri,
            String publicKeySource,
            String publicKey,
            String jwksUrl,
            List<String> claims,
            String serviceType,
            String clientType,
            String idTokenSigningAlgorithm,
            String channel,
            String landingPageUrl) {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                publicKeySource,
                                publicKey,
                                jwksUrl,
                                singletonList("openid"),
                                postlogoutUris,
                                backChannelLogoutUri,
                                serviceType,
                                "http://test.com",
                                "public",
                                claims,
                                clientType,
                                idTokenSigningAlgorithm,
                                channel,
                                false,
                                false,
                                landingPageUrl));
        assertThat(errorResponse, equalTo(Optional.empty()));
    }

    @Test
    void shouldReturnErrorForInvalidPostLogoutUriInRegistrationRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                PublicKeySource.STATIC.getValue(),
                                VALID_PUBLIC_KEY,
                                null,
                                singletonList("openid"),
                                singletonList("invalid-logout-uri"),
                                "http://example.com",
                                String.valueOf(MANDATORY),
                                "http://test.com",
                                "public",
                                emptyList(),
                                ClientType.WEB.getValue(),
                                ES256.getName(),
                                Channel.WEB.getValue(),
                                false,
                                false,
                                "http://landing-page.com"));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_POST_LOGOUT_URI)));
    }

    @Test
    void shouldReturnErrorForInvalidRedirectUriInRegistrationequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("invalid-redirect-uri"),
                                PublicKeySource.STATIC.getValue(),
                                VALID_PUBLIC_KEY,
                                null,
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                "http://example.com",
                                String.valueOf(MANDATORY),
                                "http://test.com",
                                "public",
                                emptyList(),
                                ClientType.WEB.getValue(),
                                ES256.getName(),
                                Channel.WEB.getValue(),
                                false,
                                false,
                                "http://landing-page.com"));
        assertThat(errorResponse, equalTo(Optional.of(RegistrationError.INVALID_REDIRECT_URI)));
    }

    @Test
    void shouldReturnErrorForInvalidPublicKeySourceInRegistrationRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                "invalid-public-key-source",
                                VALID_PUBLIC_KEY,
                                null,
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                "http://example.com",
                                String.valueOf(MANDATORY),
                                "http://test.com",
                                "public",
                                emptyList(),
                                ClientType.WEB.getValue(),
                                ES256.getName(),
                                Channel.WEB.getValue(),
                                false,
                                false,
                                "http://landing-page.com"));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_PUBLIC_KEY)));
    }

    @Test
    void shouldReturnErrorForInvalidPublicKeyInRegistrationRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                PublicKeySource.STATIC.getValue(),
                                "invalid-public-cert",
                                null,
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                "http://example.com",
                                String.valueOf(MANDATORY),
                                "http://test.com",
                                "public",
                                emptyList(),
                                ClientType.WEB.getValue(),
                                ES256.getName(),
                                Channel.WEB.getValue(),
                                false,
                                false,
                                "http://landing-page.com"));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_PUBLIC_KEY)));
    }

    @Test
    void shouldReturnErrorForInvalidJwksUrlInRegistrationRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                PublicKeySource.JWKS.getValue(),
                                null,
                                "invalid-jwks-url",
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                "http://example.com",
                                String.valueOf(MANDATORY),
                                "http://test.com",
                                "public",
                                emptyList(),
                                ClientType.WEB.getValue(),
                                ES256.getName(),
                                Channel.WEB.getValue(),
                                false,
                                false,
                                "http://landing-page.com"));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_JWKS_URI)));
    }

    @Test
    void shouldReturnErrorForInvalidScopesInRegistrationRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                PublicKeySource.STATIC.getValue(),
                                VALID_PUBLIC_KEY,
                                null,
                                List.of("openid", "email", "fax"),
                                singletonList("http://localhost/post-redirect-logout"),
                                "http://example.com",
                                String.valueOf(MANDATORY),
                                "http://test.com",
                                "public",
                                emptyList(),
                                ClientType.WEB.getValue(),
                                ES256.getName(),
                                Channel.WEB.getValue(),
                                false,
                                false,
                                "http://landing-page.com"));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_SCOPE)));
    }

    @Test
    void shouldReturnErrorForPrivateScopeInRegistrationRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                PublicKeySource.STATIC.getValue(),
                                VALID_PUBLIC_KEY,
                                null,
                                List.of("openid", "am"),
                                singletonList("http://localhost/post-redirect-logout"),
                                "http://example.com",
                                String.valueOf(MANDATORY),
                                "http://test.com",
                                "public",
                                emptyList(),
                                ClientType.WEB.getValue(),
                                ES256.getName(),
                                Channel.WEB.getValue(),
                                false,
                                false,
                                "http://landing-page.com"));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_SCOPE)));
    }

    @Test
    void shouldReturnErrorForInvalidClaimsInRegistrationRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                PublicKeySource.STATIC.getValue(),
                                VALID_PUBLIC_KEY,
                                null,
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                "http://example.com",
                                String.valueOf(MANDATORY),
                                "http://test.com",
                                "public",
                                List.of("name", "email"),
                                ClientType.WEB.getValue(),
                                ES256.getName(),
                                Channel.WEB.getValue(),
                                false,
                                false,
                                "http://landing-page.com"));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_CLAIM)));
    }

    @Test
    void shouldReturnErrorForInvalidClientTypeInRegistrationRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                PublicKeySource.STATIC.getValue(),
                                VALID_PUBLIC_KEY,
                                null,
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                "http://example.com",
                                String.valueOf(MANDATORY),
                                "http://test.com",
                                "public",
                                emptyList(),
                                "Mobile",
                                ES256.getName(),
                                Channel.WEB.getValue(),
                                false,
                                false,
                                "http://landing-page.com"));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_CLIENT_TYPE)));
    }

    @Test
    void shouldReturnErrorForInvalidClientLoCsInRegistrationRequest() {
        ClientRegistrationRequest regReq =
                new ClientRegistrationRequest(
                        "",
                        singletonList("http://localhost:1000/redirect"),
                        singletonList("test-client@test.com"),
                        PublicKeySource.STATIC.getValue(),
                        VALID_PUBLIC_KEY,
                        null,
                        singletonList("openid"),
                        singletonList("http://localhost/post-redirect-logout"),
                        "http://example.com",
                        String.valueOf(MANDATORY),
                        "http://test.com",
                        "public",
                        false,
                        emptyList(),
                        ClientType.WEB.getValue(),
                        ES256.getName(),
                        List.of("Unsupported_LoC"),
                        Channel.WEB.getValue(),
                        false,
                        false,
                        "http://landing-page.com");

        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(regReq);
        assertThat(errorResponse, equalTo(Optional.of(INVALID_CLIENT_LOCS)));
    }

    @ParameterizedTest
    @MethodSource("invalidAlgorithmSource")
    void shouldReturnErrorForInvalidIdTokenSigningAlgorithmInInRegistrationRequest(
            String invalidIdTokenSource) {
        ClientRegistrationRequest regReq =
                new ClientRegistrationRequest(
                        "",
                        singletonList("http://localhost:1000/redirect"),
                        singletonList("test-client@test.com"),
                        PublicKeySource.STATIC.getValue(),
                        VALID_PUBLIC_KEY,
                        null,
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
                        List.of("Unsupported_LoC"),
                        Channel.WEB.getValue(),
                        false,
                        false,
                        "http://landing-page.com");

        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(regReq);
        assertThat(errorResponse, equalTo(Optional.of(INVALID_ID_TOKEN_SIGNING_ALGORITHM)));
    }

    @Test
    void shouldReturnErrorForInvalidLandingPageUrlInRegistrationRequest() {
        ClientRegistrationRequest regReq =
                new ClientRegistrationRequest(
                        "",
                        singletonList("http://localhost:1000/redirect"),
                        singletonList("test-client@test.com"),
                        PublicKeySource.STATIC.getValue(),
                        VALID_PUBLIC_KEY,
                        null,
                        singletonList("openid"),
                        singletonList("http://localhost/post-redirect-logout"),
                        "http://example.com",
                        String.valueOf(MANDATORY),
                        "http://test.com",
                        "public",
                        false,
                        emptyList(),
                        ClientType.WEB.getValue(),
                        ES256.getName(),
                        List.of("Unsupported_LoC"),
                        Channel.WEB.getValue(),
                        false,
                        false,
                        "invalid-landing-page-url");

        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(regReq);
        assertThat(errorResponse, equalTo(Optional.of(INVALID_LANDING_PAGE_URL)));
    }

    @ParameterizedTest
    @MethodSource("subjectTypes")
    void shouldCorrectlyValidateSubjectTypeInRegistrationRequest(
            String subjectType, Optional<ErrorObject> expectedResult) {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                PublicKeySource.STATIC.getValue(),
                                VALID_PUBLIC_KEY,
                                null,
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                "http://example.com",
                                String.valueOf(MANDATORY),
                                "http://test.com",
                                subjectType,
                                emptyList(),
                                ClientType.WEB.getValue(),
                                ES256.getName(),
                                Channel.WEB.getValue(),
                                false,
                                false,
                                "http://landing-page.com"));
        assertThat(errorResponse, equalTo(expectedResult));
    }

    private static Stream<Arguments> subjectTypes() {
        return Stream.of(
                Arguments.of("public", Optional.empty()),
                Arguments.of("pairwise", Optional.empty()),
                Arguments.of("PUBLIC", Optional.of(INVALID_SUBJECT_TYPE)),
                Arguments.of("PAIRWISE", Optional.of(INVALID_SUBJECT_TYPE)));
    }

    @ParameterizedTest
    @MethodSource("validUpdateCaseSource")
    void shouldPassValidationForValidUpdateRequest(
            String idTokenSigningAlgorithm,
            String publicKeySource,
            String publicKey,
            String jwksUrl) {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientUpdateConfig(
                        generateClientUpdateRequest(
                                singletonList("http://localhost:1000/redirect"),
                                publicKeySource,
                                publicKey,
                                jwksUrl,
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                String.valueOf(MANDATORY),
                                false,
                                "http://localhost/sector-id",
                                ClientType.WEB.getValue(),
                                idTokenSigningAlgorithm,
                                List.of(LevelOfConfidence.MEDIUM_LEVEL.getValue()),
                                "http://landing-page.com"));
        assertThat(errorResponse, equalTo(Optional.empty()));
    }

    static Stream<Arguments> validUpdateCaseSource() {
        return Stream.of(
                Arguments.of(
                        ES256.getName(), PublicKeySource.STATIC.getValue(), VALID_PUBLIC_KEY, null),
                Arguments.of(
                        RS256.getName(),
                        PublicKeySource.JWKS.getValue(),
                        null,
                        "https://valid.jwks.url.gov.uk"),
                Arguments.of(RS256.getName(), null, VALID_PUBLIC_KEY, null),
                Arguments.of(RS256.getName(), null, null, null));
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
                                PublicKeySource.STATIC.getValue(),
                                VALID_PUBLIC_KEY,
                                null,
                                singletonList("openid"),
                                singletonList("invalid-logout-uri"),
                                String.valueOf(MANDATORY),
                                false,
                                null,
                                ClientType.WEB.getValue(),
                                ES256.getName(),
                                List.of(LevelOfConfidence.MEDIUM_LEVEL.getValue()),
                                null));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_POST_LOGOUT_URI)));
    }

    @Test
    void shouldReturnErrorForInvalidRedirectUriInUpdateRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientUpdateConfig(
                        generateClientUpdateRequest(
                                singletonList("invalid-redirect-uri"),
                                PublicKeySource.STATIC.getValue(),
                                VALID_PUBLIC_KEY,
                                null,
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                String.valueOf(MANDATORY),
                                false,
                                null,
                                ClientType.WEB.getValue(),
                                ES256.getName(),
                                List.of(LevelOfConfidence.MEDIUM_LEVEL.getValue()),
                                null));
        assertThat(errorResponse, equalTo(Optional.of(RegistrationError.INVALID_REDIRECT_URI)));
    }

    @Test
    void shouldReturnErrorForInvalidPublicKeySourceInUpdateRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientUpdateConfig(
                        generateClientUpdateRequest(
                                singletonList("http://localhost:1000/redirect"),
                                "invalid-public-key-source",
                                VALID_PUBLIC_KEY,
                                null,
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                String.valueOf(MANDATORY),
                                false,
                                null,
                                ES256.getName(),
                                ClientType.WEB.getValue(),
                                List.of(LevelOfConfidence.MEDIUM_LEVEL.getValue()),
                                null));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_PUBLIC_KEY_SOURCE)));
    }

    @Test
    void shouldReturnErrorForInvalidPublicKeyInUpdateRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientUpdateConfig(
                        generateClientUpdateRequest(
                                singletonList("http://localhost:1000/redirect"),
                                PublicKeySource.STATIC.getValue(),
                                "invalid-public-cert",
                                null,
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                String.valueOf(MANDATORY),
                                false,
                                null,
                                ES256.getName(),
                                ClientType.WEB.getValue(),
                                List.of(LevelOfConfidence.MEDIUM_LEVEL.getValue()),
                                null));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_PUBLIC_KEY)));
    }

    @Test
    void shouldReturnErrorForInvalidJwksUriInUpdateRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientUpdateConfig(
                        generateClientUpdateRequest(
                                singletonList("http://localhost:1000/redirect"),
                                PublicKeySource.JWKS.getValue(),
                                null,
                                "invalid-jwks-url",
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                String.valueOf(MANDATORY),
                                false,
                                null,
                                ES256.getName(),
                                ClientType.WEB.getValue(),
                                List.of(LevelOfConfidence.MEDIUM_LEVEL.getValue()),
                                null));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_JWKS_URI)));
    }

    @Test
    void shouldReturnErrorForInvalidScopesInUpdateRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientUpdateConfig(
                        generateClientUpdateRequest(
                                singletonList("http://localhost:1000/redirect"),
                                PublicKeySource.STATIC.getValue(),
                                VALID_PUBLIC_KEY,
                                null,
                                List.of("openid", "email", "fax"),
                                singletonList("http://localhost/post-redirect-logout"),
                                String.valueOf(MANDATORY),
                                false,
                                null,
                                ClientType.WEB.getValue(),
                                ES256.getName(),
                                List.of(LevelOfConfidence.MEDIUM_LEVEL.getValue()),
                                null));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_SCOPE)));
    }

    @Test
    void shouldReturnErrorForInvalidClientTypeInUpdateRequest() {
        var errorResponse =
                validationService.validateClientUpdateConfig(
                        generateClientUpdateRequest(
                                singletonList("http://localhost:1000/redirect"),
                                PublicKeySource.STATIC.getValue(),
                                VALID_PUBLIC_KEY,
                                null,
                                List.of("openid", "email"),
                                singletonList("http://localhost/post-redirect-logout"),
                                String.valueOf(MANDATORY),
                                false,
                                null,
                                ES256.getName(),
                                "rubbish-client-type",
                                List.of(LevelOfConfidence.MEDIUM_LEVEL.getValue()),
                                null));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_CLIENT_TYPE)));
    }

    @Test
    void shouldReturnErrorForInvalidClientLoCsInUpdateRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientUpdateConfig(
                        generateClientUpdateRequest(
                                singletonList("http://localhost:1000/redirect"),
                                PublicKeySource.STATIC.getValue(),
                                VALID_PUBLIC_KEY,
                                null,
                                List.of("openid", "email", "fax"),
                                singletonList("http://localhost/post-redirect-logout"),
                                String.valueOf(MANDATORY),
                                false,
                                null,
                                ClientType.WEB.getValue(),
                                ES256.getName(),
                                List.of("Unsupported_LoC"),
                                null));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_CLIENT_LOCS)));
    }

    @ParameterizedTest
    @MethodSource("invalidAlgorithmSource")
    void shouldReturnErrorForInvalidIdTokenSigningAlgorithmInUpdateRequest(
            String invalidIdTokenSigningAlgorithm) {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientUpdateConfig(
                        generateClientUpdateRequest(
                                singletonList("http://localhost:1000/redirect"),
                                PublicKeySource.STATIC.getValue(),
                                VALID_PUBLIC_KEY,
                                null,
                                List.of("openid", "email", "fax"),
                                singletonList("http://localhost/post-redirect-logout"),
                                String.valueOf(MANDATORY),
                                false,
                                null,
                                ClientType.WEB.getValue(),
                                invalidIdTokenSigningAlgorithm,
                                List.of(LevelOfConfidence.MEDIUM_LEVEL.getValue()),
                                null));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_ID_TOKEN_SIGNING_ALGORITHM)));
    }

    @Test
    void shouldReturnErrorForInvalidLandingPageUrlInUpdateRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientUpdateConfig(
                        generateClientUpdateRequest(
                                singletonList("http://localhost:1000/redirect"),
                                PublicKeySource.JWKS.getValue(),
                                null,
                                null,
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                String.valueOf(MANDATORY),
                                false,
                                null,
                                ES256.getName(),
                                ClientType.WEB.getValue(),
                                List.of(LevelOfConfidence.MEDIUM_LEVEL.getValue()),
                                "invalid-landing-page-url"));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_LANDING_PAGE_URL)));
    }

    static Stream<Arguments> invalidAlgorithmSource() {
        return Stream.of(
                Arguments.of("NOT_AN_ALGORITHM"), Arguments.of(JWSAlgorithm.PS256.getName()));
    }

    private ClientRegistrationRequest generateClientRegRequest(
            List<String> redirectUri,
            String publicKeySource,
            String publicKey,
            String jwksUrl,
            List<String> scopes,
            List<String> postLogoutUris,
            String backChannelLogoutUri,
            String serviceType,
            String sectorIdentifierUri,
            String subjectType,
            List<String> claims,
            String clientType,
            String idTokenSigningAlgorithm,
            String channel,
            boolean maxAgeEnabled,
            boolean pkceEnforced,
            String landingPageUrl) {
        return new ClientRegistrationRequest(
                "The test client",
                redirectUri,
                singletonList("test-client@test.com"),
                publicKeySource,
                publicKey,
                jwksUrl,
                scopes,
                postLogoutUris,
                backChannelLogoutUri,
                serviceType,
                sectorIdentifierUri,
                subjectType,
                false,
                claims,
                clientType,
                idTokenSigningAlgorithm,
                channel,
                maxAgeEnabled,
                pkceEnforced,
                landingPageUrl);
    }

    private UpdateClientConfigRequest generateClientUpdateRequest(
            List<String> redirectUri,
            String publicKeySource,
            String publicKey,
            String jwksUrl,
            List<String> scopes,
            List<String> postLogoutUris,
            String serviceType,
            boolean jarValidationRequired,
            String sectorURI,
            String clientType,
            String idTokenSigningAlgorithm,
            List<String> clientLoCs,
            String landingPageUrl) {
        UpdateClientConfigRequest configRequest = new UpdateClientConfigRequest();
        configRequest.setScopes(scopes);
        configRequest.setRedirectUris(redirectUri);
        configRequest.setPublicKeySource(publicKeySource);
        configRequest.setPublicKey(publicKey);
        configRequest.setJwksUrl(jwksUrl);
        configRequest.setPostLogoutRedirectUris(postLogoutUris);
        configRequest.setServiceType(serviceType);
        configRequest.setJarValidationRequired(jarValidationRequired);
        configRequest.setSectorIdentifierUri(sectorURI);
        configRequest.setClientType(clientType);
        configRequest.setIdTokenSigningAlgorithm(idTokenSigningAlgorithm);
        configRequest.setClientLoCs(clientLoCs);
        configRequest.setIdentityVerificationSupported(IDENTITY_VERIFICATION_SUPPORTED);
        configRequest.setLandingPageUrl(landingPageUrl);
        return configRequest;
    }
}
