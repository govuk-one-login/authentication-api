package uk.gov.di.services;

import org.junit.jupiter.api.Test;
import uk.gov.di.entity.ClientRegistrationRequest;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.entity.UpdateClientConfigRequest;

import java.util.List;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class ClientConfigValidationServiceTest {

    private final ClientConfigValidationService validationService =
            new ClientConfigValidationService();
    private static final String VALID_PUBLIC_CERT =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxt91w8GsMDdklOpS8ZXAsIM1ztQZd5QT/bRCQahZJeS1a6Os4hbuKwzHlz52zfTNp7BL4RB/KOcRIPhOQLgqeyM+bVngRa1EIfTkugJHS2/gu2Xv0aelwvXj8FZgAPRPD+ps2wiV4tUehrFIsRyHZM3yOp9g6qapCcxF7l0E1PlVkKPcPNmxn2oFiqnP6ZThGbE+N2avdXHcySIqt/v6Hbmk8cDHzSExazW7j/XvA+xnp0nQ5m2GisCZul5If5edCTXD0tKzx/I/gtEG4gkv9kENWOt4grP8/0zjNAl2ac6kpRny3tY5RkKBKCOB1VHwq2lUTSNKs32O1BsA5ByyYQIDAQAB";

    @Test
    public void shouldPassValidationForValidRegistrationRequest() {
        Optional<ErrorResponse> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                VALID_PUBLIC_CERT,
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout")));
        assertThat(errorResponse, equalTo(Optional.empty()));
    }

    @Test
    public void shouldReturnErrorForInvalidPostLogoutUriInRegistrationRequest() {
        Optional<ErrorResponse> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                VALID_PUBLIC_CERT,
                                singletonList("openid"),
                                singletonList("invalid-logout-uri")));
        assertThat(errorResponse, equalTo(Optional.of(ErrorResponse.ERROR_1021)));
    }

    @Test
    public void shouldReturnErrorForInvalidRedirectUriInRegistrationequest() {
        Optional<ErrorResponse> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("invalid-redirect-uri"),
                                VALID_PUBLIC_CERT,
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout")));
        assertThat(errorResponse, equalTo(Optional.of(ErrorResponse.ERROR_1022)));
    }

    @Test
    public void shouldReturnErrorForInvalidPublicKeyInRegistrationRequest() {
        Optional<ErrorResponse> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                "invalid-public-cert",
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout")));
        assertThat(errorResponse, equalTo(Optional.of(ErrorResponse.ERROR_1023)));
    }

    @Test
    public void shouldReturnErrorForInvalidScopesInRegistrationRequest() {
        Optional<ErrorResponse> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                VALID_PUBLIC_CERT,
                                List.of("openid", "email", "fax"),
                                singletonList("http://localhost/post-redirect-logout")));
        assertThat(errorResponse, equalTo(Optional.of(ErrorResponse.ERROR_1024)));
    }

    @Test
    public void shouldPassValidationForValidUpdateRequest() {
        Optional<ErrorResponse> errorResponse =
                validationService.validateClientUpdateConfig(
                        generateClientUpdateRequest(
                                singletonList("http://localhost:1000/redirect"),
                                VALID_PUBLIC_CERT,
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout")));
        assertThat(errorResponse, equalTo(Optional.empty()));
    }

    @Test
    public void shouldReturnOptionalEmptyForEmptyUpdateRequest() {
        Optional<ErrorResponse> errorResponse =
                validationService.validateClientUpdateConfig(new UpdateClientConfigRequest());
        assertThat(errorResponse, equalTo(Optional.empty()));
    }

    @Test
    public void shouldReturnErrorForInvalidPostLogoutUriInUpdateRequest() {
        Optional<ErrorResponse> errorResponse =
                validationService.validateClientUpdateConfig(
                        generateClientUpdateRequest(
                                singletonList("http://localhost:1000/redirect"),
                                VALID_PUBLIC_CERT,
                                singletonList("openid"),
                                singletonList("invalid-logout-uri")));
        assertThat(errorResponse, equalTo(Optional.of(ErrorResponse.ERROR_1021)));
    }

    @Test
    public void shouldReturnErrorForInvalidRedirectUriInUpdateRequest() {
        Optional<ErrorResponse> errorResponse =
                validationService.validateClientUpdateConfig(
                        generateClientUpdateRequest(
                                singletonList("invalid-redirect-uri"),
                                VALID_PUBLIC_CERT,
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout")));
        assertThat(errorResponse, equalTo(Optional.of(ErrorResponse.ERROR_1022)));
    }

    @Test
    public void shouldReturnErrorForInvalidPublicKeyInUpdateRequest() {
        Optional<ErrorResponse> errorResponse =
                validationService.validateClientUpdateConfig(
                        generateClientUpdateRequest(
                                singletonList("http://localhost:1000/redirect"),
                                "invalid-public-cert",
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout")));
        assertThat(errorResponse, equalTo(Optional.of(ErrorResponse.ERROR_1023)));
    }

    @Test
    public void shouldReturnErrorForInvalidScopesInUpdateRequest() {
        Optional<ErrorResponse> errorResponse =
                validationService.validateClientUpdateConfig(
                        generateClientUpdateRequest(
                                singletonList("http://localhost:1000/redirect"),
                                VALID_PUBLIC_CERT,
                                List.of("openid", "email", "fax"),
                                singletonList("http://localhost/post-redirect-logout")));
        assertThat(errorResponse, equalTo(Optional.of(ErrorResponse.ERROR_1024)));
    }

    private ClientRegistrationRequest generateClientRegRequest(
            List<String> redirectUri,
            String publicCert,
            List<String> scopes,
            List<String> postLogoutUris) {
        return new ClientRegistrationRequest(
                "The test client",
                redirectUri,
                singletonList("test-client@test.com"),
                publicCert,
                scopes,
                postLogoutUris);
    }

    private UpdateClientConfigRequest generateClientUpdateRequest(
            List<String> redirectUri,
            String publicCert,
            List<String> scopes,
            List<String> postLogoutUris) {
        UpdateClientConfigRequest configRequest = new UpdateClientConfigRequest();
        configRequest.setScopes(scopes);
        configRequest.setRedirectUris(redirectUri);
        configRequest.setPublicKey(publicCert);
        configRequest.setPostLogoutRedirectUris(postLogoutUris);
        return configRequest;
    }
}
