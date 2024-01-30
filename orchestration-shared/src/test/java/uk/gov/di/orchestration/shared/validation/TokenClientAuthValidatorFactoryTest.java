package uk.gov.di.orchestration.shared.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.sharedtest.helper.KeyPairHelper;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.helpers.RequestBodyHelper.parseRequestBody;

class TokenClientAuthValidatorFactoryTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private static final ClientID CLIENT_ID = new ClientID();
    private static final Secret CLIENT_SECRET = new Secret();
    private final TokenClientAuthValidatorFactory tokenClientAuthValidatorFactory =
            new TokenClientAuthValidatorFactory(configurationService, dynamoClientService);

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldReturnPrivateKeyJwtClientAuthValidator(boolean clientSecretSupported)
            throws JOSEException {
        when(configurationService.isClientSecretSupported()).thenReturn(clientSecretSupported);
        var claimsSet =
                new JWTAuthenticationClaimsSet(new ClientID(), new Audience("https://oidc/token"));
        var privateKeyJWT =
                new PrivateKeyJWT(
                        claimsSet,
                        JWSAlgorithm.RS256,
                        KeyPairHelper.GENERATE_RSA_KEY_PAIR().getPrivate(),
                        null,
                        null);

        var tokenAuthenticationValidator =
                tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(
                        parseRequestBody(
                                URLUtils.serializeParameters(privateKeyJWT.toParameters())));

        assertInstanceOf(
                PrivateKeyJwtClientAuthValidator.class, tokenAuthenticationValidator.get());
    }

    @Test
    void shouldReturnClientSecretPostClientAuthValidator() {
        when(configurationService.isClientSecretSupported()).thenReturn(true);
        var clientSecretPost = new ClientSecretPost(CLIENT_ID, CLIENT_SECRET);
        var requestString =
                parseRequestBody(URLUtils.serializeParameters(clientSecretPost.toParameters()));

        var tokenAuthenticationValidator =
                tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(requestString);

        assertInstanceOf(
                ClientSecretPostClientAuthValidator.class, tokenAuthenticationValidator.get());
    }

    @Test
    void shouldReturnEmptyWhenClientSecretPostButIsNotYetSupported() {
        when(configurationService.isClientSecretSupported()).thenReturn(false);
        var clientSecretPost = new ClientSecretPost(CLIENT_ID, CLIENT_SECRET);
        var requestString =
                parseRequestBody(URLUtils.serializeParameters(clientSecretPost.toParameters()));

        var tokenAuthenticationValidator =
                tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(requestString);

        assertThat(tokenAuthenticationValidator, equalTo(Optional.empty()));
    }
}
