package uk.gov.di.orchestration.shared.validation;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.exceptions.TokenAuthInvalidException;
import uk.gov.di.orchestration.shared.helpers.Argon2EncoderHelper;
import uk.gov.di.orchestration.shared.services.DynamoClientService;

import java.util.Objects;
import java.util.Optional;

import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

// QualityGateUnitTest
class ClientSecretPostClientAuthValidatorTest {

    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private ClientSecretPostClientAuthValidator clientSecretPostClientAuthValidator;

    private static final ClientID CLIENT_ID = new ClientID();
    private static final Secret CLIENT_SECRET = new Secret();

    @BeforeEach
    void setUp() {
        clientSecretPostClientAuthValidator =
                new ClientSecretPostClientAuthValidator(dynamoClientService);
    }

    // QualityGateRegressionTest
    @Test
    void shouldSuccessfullyValidateClientSecretPostAndReturnClientRegistry()
            throws TokenAuthInvalidException {
        var expectedClientRegistry =
                generateClientRegistry(
                        ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue(),
                        Argon2EncoderHelper.argon2Hash(CLIENT_SECRET.getValue()));
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(expectedClientRegistry));
        var clientSecretPost = new ClientSecretPost(CLIENT_ID, CLIENT_SECRET);
        var requestString = URLUtils.serializeParameters(clientSecretPost.toParameters());

        var clientRegistryOutput =
                clientSecretPostClientAuthValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                        requestString, emptyMap());

        assertTrue(Objects.nonNull(clientRegistryOutput));
        assertThat(
                clientRegistryOutput.getClientID(), equalTo(expectedClientRegistry.getClientID()));
    }

    // QualityGateRegressionTest
    @Test
    void shouldThrowIfClientIsNotFoundInClientRegistry() {
        var clientSecretPost = new ClientSecretPost(CLIENT_ID, CLIENT_SECRET);
        var requestString = URLUtils.serializeParameters(clientSecretPost.toParameters());

        TokenAuthInvalidException tokenAuthInvalidException =
                assertThrows(
                        TokenAuthInvalidException.class,
                        () ->
                                clientSecretPostClientAuthValidator
                                        .validateTokenAuthAndReturnClientRegistryIfValid(
                                                requestString, emptyMap()),
                        "Expected to throw exception");

        assertThat(tokenAuthInvalidException.getClientId(), equalTo("unknown"));
        assertThat(tokenAuthInvalidException.getErrorObject(), equalTo(OAuth2Error.INVALID_CLIENT));
    }

    // QualityGateRegressionTest
    @Test
    void shouldThrowIfClientRegistryDoesNotSupportClientSecretPost() {
        var expectedClientRegistry =
                generateClientRegistry(
                        null, Argon2EncoderHelper.argon2Hash(CLIENT_SECRET.getValue()));
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(expectedClientRegistry));
        var clientSecretPost = new ClientSecretPost(CLIENT_ID, CLIENT_SECRET);
        var requestString = URLUtils.serializeParameters(clientSecretPost.toParameters());

        var tokenAuthInvalidException =
                assertThrows(
                        TokenAuthInvalidException.class,
                        () ->
                                clientSecretPostClientAuthValidator
                                        .validateTokenAuthAndReturnClientRegistryIfValid(
                                                requestString, emptyMap()),
                        "Expected to throw exception");

        assertThat(tokenAuthInvalidException.getClientId(), equalTo(CLIENT_ID.getValue()));
        assertThat(
                tokenAuthInvalidException.getErrorObject(),
                samePropertyValuesAs(
                        new ErrorObject(
                                OAuth2Error.INVALID_CLIENT_CODE,
                                "Client is not registered to use client_secret_post")));
    }

    // QualityGateRegressionTest
    @Test
    void shouldThrowIfNoClientSecretIsRegisteredWhenValidatingClientSecretPost() {
        var expectedClientRegistry =
                generateClientRegistry(
                        ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue(), null);
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(expectedClientRegistry));
        var clientSecretPost = new ClientSecretPost(CLIENT_ID, CLIENT_SECRET);
        var requestString = URLUtils.serializeParameters(clientSecretPost.toParameters());

        var tokenAuthInvalidException =
                assertThrows(
                        TokenAuthInvalidException.class,
                        () ->
                                clientSecretPostClientAuthValidator
                                        .validateTokenAuthAndReturnClientRegistryIfValid(
                                                requestString, emptyMap()),
                        "Expected to throw exception");

        assertThat(tokenAuthInvalidException.getClientId(), equalTo(CLIENT_ID.getValue()));
        assertThat(
                tokenAuthInvalidException.getErrorObject(),
                equalTo(
                        new ErrorObject(
                                OAuth2Error.INVALID_CLIENT_CODE, "No client secret registered")));
    }

    // QualityGateRegressionTest
    @Test
    void shouldThrowIfClientSecretIsInvalidWhenValidatingClientSecretPost() {
        var expectedClientRegistry =
                generateClientRegistry(
                        ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue(),
                        Argon2EncoderHelper.argon2Hash(new Secret().getValue()));
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(expectedClientRegistry));
        var clientSecretPost = new ClientSecretPost(CLIENT_ID, CLIENT_SECRET);
        var requestString = URLUtils.serializeParameters(clientSecretPost.toParameters());

        var tokenAuthInvalidException =
                assertThrows(
                        TokenAuthInvalidException.class,
                        () ->
                                clientSecretPostClientAuthValidator
                                        .validateTokenAuthAndReturnClientRegistryIfValid(
                                                requestString, emptyMap()),
                        "Expected to throw exception");

        assertThat(tokenAuthInvalidException.getClientId(), equalTo(CLIENT_ID.getValue()));
        assertThat(
                tokenAuthInvalidException.getErrorObject(),
                equalTo(new ErrorObject(OAuth2Error.INVALID_CLIENT_CODE, "Invalid client secret")));
    }

    // QualityGateRegressionTest
    @Test
    void shouldThrowWhenUnableToParseClientSecretPost() {
        var tokenAuthInvalidException =
                assertThrows(
                        TokenAuthInvalidException.class,
                        () ->
                                clientSecretPostClientAuthValidator
                                        .validateTokenAuthAndReturnClientRegistryIfValid(
                                                "rubbish-client-secret-post", emptyMap()),
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
