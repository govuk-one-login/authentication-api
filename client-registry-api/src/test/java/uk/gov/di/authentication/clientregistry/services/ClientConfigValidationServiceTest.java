package uk.gov.di.authentication.clientregistry.services;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.client.RegistrationError;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.clientregistry.entity.ClientRegistrationRequest;
import uk.gov.di.authentication.shared.entity.UpdateClientConfigRequest;

import java.util.List;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_POST_LOGOUT_URI;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_PUBLIC_KEY;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_SCOPE;
import static uk.gov.di.authentication.shared.entity.ServiceType.MANDATORY;

class ClientConfigValidationServiceTest {

    private final ClientConfigValidationService validationService =
            new ClientConfigValidationService();
    private static final String VALID_PUBLIC_CERT =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxt91w8GsMDdklOpS8ZXAsIM1ztQZd5QT/bRCQahZJeS1a6Os4hbuKwzHlz52zfTNp7BL4RB/KOcRIPhOQLgqeyM+bVngRa1EIfTkugJHS2/gu2Xv0aelwvXj8FZgAPRPD+ps2wiV4tUehrFIsRyHZM3yOp9g6qapCcxF7l0E1PlVkKPcPNmxn2oFiqnP6ZThGbE+N2avdXHcySIqt/v6Hbmk8cDHzSExazW7j/XvA+xnp0nQ5m2GisCZul5If5edCTXD0tKzx/I/gtEG4gkv9kENWOt4grP8/0zjNAl2ac6kpRny3tY5RkKBKCOB1VHwq2lUTSNKs32O1BsA5ByyYQIDAQAB";

    @Test
    public void shouldPassValidationForValidRegistrationRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                VALID_PUBLIC_CERT,
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                String.valueOf(MANDATORY)));
        assertThat(errorResponse, equalTo(Optional.empty()));
    }

    @Test
    public void shouldReturnErrorForInvalidPostLogoutUriInRegistrationRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                VALID_PUBLIC_CERT,
                                singletonList("openid"),
                                singletonList("invalid-logout-uri"),
                                String.valueOf(MANDATORY)));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_POST_LOGOUT_URI)));
    }

    @Test
    public void shouldReturnErrorForInvalidRedirectUriInRegistrationequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("invalid-redirect-uri"),
                                VALID_PUBLIC_CERT,
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                String.valueOf(MANDATORY)));
        assertThat(errorResponse, equalTo(Optional.of(RegistrationError.INVALID_REDIRECT_URI)));
    }

    @Test
    public void shouldReturnErrorForInvalidPublicKeyInRegistrationRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                "invalid-public-cert",
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                String.valueOf(MANDATORY)));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_PUBLIC_KEY)));
    }

    @Test
    public void shouldReturnErrorForInvalidScopesInRegistrationRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                VALID_PUBLIC_CERT,
                                List.of("openid", "email", "fax"),
                                singletonList("http://localhost/post-redirect-logout"),
                                String.valueOf(MANDATORY)));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_SCOPE)));
    }

    @Test
    public void shouldReturnErrorForPrivateScopeInRegistrationRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientRegistrationConfig(
                        generateClientRegRequest(
                                singletonList("http://localhost:1000/redirect"),
                                VALID_PUBLIC_CERT,
                                List.of("openid", "am"),
                                singletonList("http://localhost/post-redirect-logout"),
                                String.valueOf(MANDATORY)));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_SCOPE)));
    }

    @Test
    public void shouldPassValidationForValidUpdateRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientUpdateConfig(
                        generateClientUpdateRequest(
                                singletonList("http://localhost:1000/redirect"),
                                VALID_PUBLIC_CERT,
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                String.valueOf(MANDATORY)));
        assertThat(errorResponse, equalTo(Optional.empty()));
    }

    @Test
    public void shouldReturnOptionalEmptyForEmptyUpdateRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientUpdateConfig(new UpdateClientConfigRequest());
        assertThat(errorResponse, equalTo(Optional.empty()));
    }

    @Test
    public void shouldReturnErrorForInvalidPostLogoutUriInUpdateRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientUpdateConfig(
                        generateClientUpdateRequest(
                                singletonList("http://localhost:1000/redirect"),
                                VALID_PUBLIC_CERT,
                                singletonList("openid"),
                                singletonList("invalid-logout-uri"),
                                String.valueOf(MANDATORY)));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_POST_LOGOUT_URI)));
    }

    @Test
    public void shouldReturnErrorForInvalidRedirectUriInUpdateRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientUpdateConfig(
                        generateClientUpdateRequest(
                                singletonList("invalid-redirect-uri"),
                                VALID_PUBLIC_CERT,
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                String.valueOf(MANDATORY)));
        assertThat(errorResponse, equalTo(Optional.of(RegistrationError.INVALID_REDIRECT_URI)));
    }

    @Test
    public void shouldReturnErrorForInvalidPublicKeyInUpdateRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientUpdateConfig(
                        generateClientUpdateRequest(
                                singletonList("http://localhost:1000/redirect"),
                                "invalid-public-cert",
                                singletonList("openid"),
                                singletonList("http://localhost/post-redirect-logout"),
                                String.valueOf(MANDATORY)));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_PUBLIC_KEY)));
    }

    @Test
    public void shouldReturnErrorForInvalidScopesInUpdateRequest() {
        Optional<ErrorObject> errorResponse =
                validationService.validateClientUpdateConfig(
                        generateClientUpdateRequest(
                                singletonList("http://localhost:1000/redirect"),
                                VALID_PUBLIC_CERT,
                                List.of("openid", "email", "fax"),
                                singletonList("http://localhost/post-redirect-logout"),
                                String.valueOf(MANDATORY)));
        assertThat(errorResponse, equalTo(Optional.of(INVALID_SCOPE)));
    }

    private ClientRegistrationRequest generateClientRegRequest(
            List<String> redirectUri,
            String publicCert,
            List<String> scopes,
            List<String> postLogoutUris,
            String serviceType) {
        return new ClientRegistrationRequest(
                "The test client",
                redirectUri,
                singletonList("test-client@test.com"),
                publicCert,
                scopes,
                postLogoutUris,
                serviceType);
    }

    private UpdateClientConfigRequest generateClientUpdateRequest(
            List<String> redirectUri,
            String publicCert,
            List<String> scopes,
            List<String> postLogoutUris,
            String serviceType) {
        UpdateClientConfigRequest configRequest = new UpdateClientConfigRequest();
        configRequest.setScopes(scopes);
        configRequest.setRedirectUris(redirectUri);
        configRequest.setPublicKey(publicCert);
        configRequest.setPostLogoutRedirectUris(postLogoutUris);
        configRequest.setServiceType(serviceType);
        return configRequest;
    }
}
