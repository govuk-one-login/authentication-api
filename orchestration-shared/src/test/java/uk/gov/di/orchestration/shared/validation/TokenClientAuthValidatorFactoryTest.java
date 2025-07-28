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
import uk.gov.di.orchestration.shared.services.ClientSignatureValidationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.sharedtest.helper.KeyPairHelper;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.Mockito.mock;
import static uk.gov.di.orchestration.shared.helpers.RequestBodyHelper.parseRequestBody;

class TokenClientAuthValidatorFactoryTest {

    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final ClientSignatureValidationService clientSignatureValidationService =
            mock(ClientSignatureValidationService.class);
    private static final ClientID CLIENT_ID = new ClientID();
    private static final Secret CLIENT_SECRET = new Secret();
    private final TokenClientAuthValidatorFactory tokenClientAuthValidatorFactory =
            new TokenClientAuthValidatorFactory(
                    dynamoClientService, clientSignatureValidationService);

    @Test
    void shouldReturnPrivateKeyJwtClientAuthValidator() throws JOSEException {
        var claimsSet =
                new JWTAuthenticationClaimsSet(new ClientID(), new Audience("https://oidc/token"));
        var privateKeyJWT =
                new PrivateKeyJWT(
                        claimsSet,
                        JWSAlgorithm.RS256,
                        KeyPairHelper.generateRsaKeyPair().getPrivate(),
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
        var clientSecretPost = new ClientSecretPost(CLIENT_ID, CLIENT_SECRET);
        var requestString =
                parseRequestBody(URLUtils.serializeParameters(clientSecretPost.toParameters()));

        var tokenAuthenticationValidator =
                tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(requestString);

        assertInstanceOf(
                ClientSecretPostClientAuthValidator.class, tokenAuthenticationValidator.get());
    }
}
