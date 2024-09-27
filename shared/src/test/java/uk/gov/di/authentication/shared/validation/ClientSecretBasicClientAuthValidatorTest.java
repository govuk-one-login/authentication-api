package uk.gov.di.authentication.shared.validation;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.exceptions.TokenAuthInvalidException;
import uk.gov.di.authentication.shared.helpers.Argon2EncoderHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ClientSecretBasicClientAuthValidatorTest {

    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private ClientSecretBasicClientAuthValidator clientSecretBasicClientAuthValidator;

    private static final ClientID CLIENT_ID = new ClientID();
    private static final Secret CLIENT_SECRET = new Secret();

    @BeforeEach
    void setUp() {
        when(configurationService.getHeadersCaseInsensitive()).thenReturn(true);
        clientSecretBasicClientAuthValidator =
                new ClientSecretBasicClientAuthValidator(dynamoClientService, configurationService);
    }

    @Test
    void shouldSuccessfullyValidateClientSecretBasicAndReturnClientRegistry()
            throws TokenAuthInvalidException {
        var expectedClientRegistry =
                generateClientRegistry(
                        ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue(),
                        Argon2EncoderHelper.argon2Hash(CLIENT_SECRET.getValue()));
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(expectedClientRegistry));
        var clientSecretBasic = new ClientSecretBasic(CLIENT_ID, CLIENT_SECRET);

        var clientRegistryOutput =
                clientSecretBasicClientAuthValidator
                        .validateTokenAuthAndReturnClientRegistryIfValid(
                                null,
                                Map.of(
                                        "Authorization",
                                        clientSecretBasic.toHTTPAuthorizationHeader()));

        assertTrue(Objects.nonNull(clientRegistryOutput));
        assertThat(
                clientRegistryOutput.getClientID(), equalTo(expectedClientRegistry.getClientID()));
    }

    @Test
    void shouldThrowIfClientIsNotFoundInClientRegistry() {
        var clientSecretBasic = new ClientSecretBasic(CLIENT_ID, CLIENT_SECRET);

        TokenAuthInvalidException tokenAuthInvalidException =
                assertThrows(
                        TokenAuthInvalidException.class,
                        () ->
                                clientSecretBasicClientAuthValidator
                                        .validateTokenAuthAndReturnClientRegistryIfValid(
                                                null,
                                                Map.of(
                                                        "Authorization",
                                                        clientSecretBasic
                                                                .toHTTPAuthorizationHeader())),
                        "Expected to throw exception");

        assertThat(tokenAuthInvalidException.getClientId(), equalTo("unknown"));
        assertThat(tokenAuthInvalidException.getErrorObject(), equalTo(OAuth2Error.INVALID_CLIENT));
    }

    @Test
    void shouldThrowIfClientRegistryDoesNotSupportClientSecretBasic() {
        var expectedClientRegistry =
                generateClientRegistry(
                        null, Argon2EncoderHelper.argon2Hash(CLIENT_SECRET.getValue()));
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(expectedClientRegistry));
        var clientSecretBasic = new ClientSecretBasic(CLIENT_ID, CLIENT_SECRET);

        var tokenAuthInvalidException =
                assertThrows(
                        TokenAuthInvalidException.class,
                        () ->
                                clientSecretBasicClientAuthValidator
                                        .validateTokenAuthAndReturnClientRegistryIfValid(
                                                null,
                                                Map.of(
                                                        "Authorization",
                                                        clientSecretBasic
                                                                .toHTTPAuthorizationHeader())),
                        "Expected to throw exception");

        assertThat(tokenAuthInvalidException.getClientId(), equalTo(CLIENT_ID.getValue()));
        assertThat(
                tokenAuthInvalidException.getErrorObject(),
                equalTo(
                        new ErrorObject(
                                OAuth2Error.INVALID_CLIENT_CODE,
                                "Client is not registered to use client_secret_basic")));
    }

    @Test
    void shouldThrowIfNoClientSecretIsRegisteredWhenValidatingClientSecretBasic() {
        var expectedClientRegistry =
                generateClientRegistry(
                        ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue(), null);
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(expectedClientRegistry));
        var clientSecretBasic = new ClientSecretBasic(CLIENT_ID, CLIENT_SECRET);

        var tokenAuthInvalidException =
                assertThrows(
                        TokenAuthInvalidException.class,
                        () ->
                                clientSecretBasicClientAuthValidator
                                        .validateTokenAuthAndReturnClientRegistryIfValid(
                                                null,
                                                Map.of(
                                                        "Authorization",
                                                        clientSecretBasic
                                                                .toHTTPAuthorizationHeader())),
                        "Expected to throw exception");

        assertThat(tokenAuthInvalidException.getClientId(), equalTo(CLIENT_ID.getValue()));
        assertThat(
                tokenAuthInvalidException.getErrorObject(),
                equalTo(
                        new ErrorObject(
                                OAuth2Error.INVALID_CLIENT_CODE, "No client secret registered")));
    }

    @Test
    void shouldThrowIfClientSecretIsInvalidWhenValidatingClientSecretBasic() {
        var expectedClientRegistry =
                generateClientRegistry(
                        ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue(),
                        Argon2EncoderHelper.argon2Hash(new Secret().getValue()));
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(expectedClientRegistry));
        var clientSecretBasic = new ClientSecretBasic(CLIENT_ID, CLIENT_SECRET);

        var tokenAuthInvalidException =
                assertThrows(
                        TokenAuthInvalidException.class,
                        () ->
                                clientSecretBasicClientAuthValidator
                                        .validateTokenAuthAndReturnClientRegistryIfValid(
                                                null,
                                                Map.of(
                                                        "Authorization",
                                                        clientSecretBasic
                                                                .toHTTPAuthorizationHeader())),
                        "Expected to throw exception");

        assertThat(tokenAuthInvalidException.getClientId(), equalTo(CLIENT_ID.getValue()));
        assertThat(
                tokenAuthInvalidException.getErrorObject(),
                equalTo(new ErrorObject(OAuth2Error.INVALID_CLIENT_CODE, "Invalid client secret")));
    }

    @Test
    void shouldThrowWhenUnableToParseClientSecretBasic() {
        var tokenAuthInvalidException =
                assertThrows(
                        TokenAuthInvalidException.class,
                        () ->
                                clientSecretBasicClientAuthValidator
                                        .validateTokenAuthAndReturnClientRegistryIfValid(
                                                null,
                                                Map.of(
                                                        "Authorization",
                                                        "rubbish-client-secret-basic")),
                        "Expected to throw exception");

        assertThat(tokenAuthInvalidException.getClientId(), equalTo("unknown"));
        assertThat(
                tokenAuthInvalidException.getErrorObject(), equalTo(OAuth2Error.INVALID_REQUEST));
    }

    private ClientRegistry generateClientRegistry(String tokenAuthMethod, String clientSecret) {
        return new ClientRegistry()
                .withRedirectUrls(singletonList("https://localhost:8080"))
                .withClientID(CLIENT_ID.getValue())
                .withContacts(singletonList("joe.bloggs@digital.cabinet-office.gov.uk"))
                .withPublicKey(null)
                .withScopes(singletonList("openid"))
                .withCookieConsentShared(true)
                .withTokenAuthMethod(tokenAuthMethod)
                .withClientSecret(clientSecret);
    }
}
