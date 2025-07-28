package uk.gov.di.orchestration.shared.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.exceptions.ClientSignatureValidationException;
import uk.gov.di.orchestration.shared.exceptions.JwksException;
import uk.gov.di.orchestration.shared.exceptions.TokenAuthInvalidException;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.ClientSignatureValidationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.sharedtest.helper.KeyPairHelper;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Optional;
import java.util.stream.Stream;

import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PrivateKeyJwtClientAuthValidatorTest {

    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final ClientSignatureValidationService clientSignatureValidationService =
            mock(ClientSignatureValidationService.class);
    private OidcAPI oidcAPI = mock(OidcAPI.class);
    private static final URI OIDC_TOKEN_URL = URI.create("https://example.com/token");
    private static final ClientID CLIENT_ID = new ClientID();
    private static final KeyPair RSA_KEY_PAIR = KeyPairHelper.generateRsaKeyPair();
    private PrivateKeyJwtClientAuthValidator privateKeyJwtClientAuthValidator;

    @BeforeEach
    void setUp() {
        when(oidcAPI.tokenURI()).thenReturn(OIDC_TOKEN_URL);
        privateKeyJwtClientAuthValidator =
                new PrivateKeyJwtClientAuthValidator(
                        dynamoClientService, clientSignatureValidationService);
    }

    private static Stream<JWSAlgorithm> supportedAlgorithms() {
        return Stream.of(
                JWSAlgorithm.RS256,
                JWSAlgorithm.RS384,
                JWSAlgorithm.RS512,
                JWSAlgorithm.PS256,
                JWSAlgorithm.PS384,
                JWSAlgorithm.PS512);
    }

    @ParameterizedTest
    @MethodSource("supportedAlgorithms")
    void shouldSuccessfullyValidatePrivateKeyJWT(JWSAlgorithm algorithm)
            throws JOSEException, TokenAuthInvalidException {
        var publicKey =
                Base64.getMimeEncoder().encodeToString(RSA_KEY_PAIR.getPublic().getEncoded());
        var expiryDate = NowHelper.nowPlus(5, ChronoUnit.MINUTES);
        var expectedClientRegistry =
                generateClientRegistry(
                        publicKey, ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue());
        var requestString = generateSerialisedPrivateKeyJWT(algorithm, expiryDate.getTime());
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(expectedClientRegistry));

        var clientRegistryOutput =
                privateKeyJwtClientAuthValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                        requestString, emptyMap());

        assertThat(
                clientRegistryOutput.getClientID(), equalTo(expectedClientRegistry.getClientID()));
    }

    @Test
    void shouldSuccessfullyValidatePrivateKeyJWTWhenAuthenticationIsNotRegisteredInClientRegistry()
            throws JOSEException, TokenAuthInvalidException {
        var publicKey =
                Base64.getMimeEncoder().encodeToString(RSA_KEY_PAIR.getPublic().getEncoded());
        var expiryDate = NowHelper.nowPlus(5, ChronoUnit.MINUTES);
        var expectedClientRegistry = generateClientRegistry(publicKey, null);
        var requestString =
                generateSerialisedPrivateKeyJWT(JWSAlgorithm.RS256, expiryDate.getTime());
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(expectedClientRegistry));

        var clientRegistryOutput =
                privateKeyJwtClientAuthValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                        requestString, emptyMap());

        assertThat(
                clientRegistryOutput.getClientID(), equalTo(expectedClientRegistry.getClientID()));
    }

    @Test
    void shouldThrowClientsAuthenticationMethodIsClientSecretPost() throws JOSEException {
        var publicKey =
                Base64.getMimeEncoder().encodeToString(RSA_KEY_PAIR.getPublic().getEncoded());
        var expectedClientRegistry =
                generateClientRegistry(
                        publicKey, ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue());
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(expectedClientRegistry));
        var requestString =
                generateSerialisedPrivateKeyJWT(
                        JWSAlgorithm.RS256, NowHelper.nowMinus(2, ChronoUnit.MINUTES).getTime());

        TokenAuthInvalidException tokenAuthInvalidException =
                assertThrows(
                        TokenAuthInvalidException.class,
                        () ->
                                privateKeyJwtClientAuthValidator
                                        .validateTokenAuthAndReturnClientRegistryIfValid(
                                                requestString, emptyMap()),
                        "Expected to throw exception");

        assertThat(tokenAuthInvalidException.getClientId(), equalTo(CLIENT_ID.getValue()));
        assertThat(
                tokenAuthInvalidException.getErrorObject(),
                equalTo(
                        new ErrorObject(
                                OAuth2Error.INVALID_CLIENT_CODE,
                                "Client is not registered to use private_key_jwt")));
    }

    @Test
    void shouldThrowWhenUnableToValidatePrivateKeyJWTIfExpired() throws JOSEException {
        var publicKey =
                Base64.getMimeEncoder().encodeToString(RSA_KEY_PAIR.getPublic().getEncoded());
        var expectedClientRegistry = generateClientRegistry(publicKey, null);
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(expectedClientRegistry));
        var requestString =
                generateSerialisedPrivateKeyJWT(
                        JWSAlgorithm.RS256, NowHelper.nowMinus(2, ChronoUnit.MINUTES).getTime());

        TokenAuthInvalidException tokenAuthInvalidException =
                assertThrows(
                        TokenAuthInvalidException.class,
                        () ->
                                privateKeyJwtClientAuthValidator
                                        .validateTokenAuthAndReturnClientRegistryIfValid(
                                                requestString, emptyMap()),
                        "Expected to throw exception");

        assertThat(tokenAuthInvalidException.getClientId(), equalTo(CLIENT_ID.getValue()));
        assertThat(
                tokenAuthInvalidException.getErrorObject(),
                equalTo(
                        new ErrorObject(
                                OAuth2Error.INVALID_GRANT_CODE, "private_key_jwt has expired")));
    }

    @Test
    void shouldSuccessfullyValidatePrivateKeyJWTIfExpiredButWithinClockSkew()
            throws JOSEException, TokenAuthInvalidException {
        var publicKey =
                Base64.getMimeEncoder().encodeToString(RSA_KEY_PAIR.getPublic().getEncoded());
        var expectedClientRegistry = generateClientRegistry(publicKey, null);
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(expectedClientRegistry));
        var requestString =
                generateSerialisedPrivateKeyJWT(
                        JWSAlgorithm.RS256, NowHelper.nowMinus(15, ChronoUnit.SECONDS).getTime());

        var clientRegistryOutput =
                privateKeyJwtClientAuthValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                        requestString, emptyMap());

        assertThat(
                clientRegistryOutput.getClientID(), equalTo(expectedClientRegistry.getClientID()));
    }

    @Test
    void shouldThrowIfUnableToValidatePrivateKeyJWTSignature()
            throws JOSEException, ClientSignatureValidationException, JwksException {
        var invalidKeyPair = generateRsaKeyPair();
        var publicKey =
                Base64.getMimeEncoder().encodeToString(invalidKeyPair.getPublic().getEncoded());
        var expectedClientRegistry = generateClientRegistry(publicKey, null);
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(expectedClientRegistry));
        var requestString =
                generateSerialisedPrivateKeyJWT(
                        JWSAlgorithm.RS256, NowHelper.nowPlus(5, ChronoUnit.MINUTES).getTime());

        doThrow(ClientSignatureValidationException.class)
                .when(clientSignatureValidationService)
                .validateTokenClientAssertion(any(PrivateKeyJWT.class), any(ClientRegistry.class));

        TokenAuthInvalidException tokenAuthInvalidException =
                assertThrows(
                        TokenAuthInvalidException.class,
                        () ->
                                privateKeyJwtClientAuthValidator
                                        .validateTokenAuthAndReturnClientRegistryIfValid(
                                                requestString, emptyMap()),
                        "Expected to throw exception");

        assertThat(tokenAuthInvalidException.getClientId(), equalTo("unknown"));
        assertThat(
                tokenAuthInvalidException.getErrorObject(),
                equalTo(
                        new ErrorObject(
                                OAuth2Error.INVALID_CLIENT_CODE,
                                "Invalid signature in private_key_jwt")));
    }

    private ClientRegistry generateClientRegistry(String publicKey, String authenticationMethod) {
        return new ClientRegistry()
                .withRedirectUrls(singletonList("https://localhost:8080"))
                .withClientID(CLIENT_ID.getValue())
                .withContacts(singletonList("joe.bloggs@digital.cabinet-office.gov.uk"))
                .withPublicKeySource("STATIC")
                .withPublicKey(publicKey)
                .withScopes(singletonList("openid"))
                .withCookieConsentShared(true)
                .withTokenAuthMethod(authenticationMethod);
    }

    private String generateSerialisedPrivateKeyJWT(JWSAlgorithm algorithm, long expiryTime)
            throws JOSEException {
        var claimsSet = new JWTAuthenticationClaimsSet(CLIENT_ID, new Audience(OIDC_TOKEN_URL));
        claimsSet.getExpirationTime().setTime(expiryTime);
        var privateKeyJWT =
                new PrivateKeyJWT(claimsSet, algorithm, RSA_KEY_PAIR.getPrivate(), null, null);
        var privateKeyParams = privateKeyJWT.toParameters();
        return URLUtils.serializeParameters(privateKeyParams);
    }

    private KeyPair generateRsaKeyPair() {
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }
}
