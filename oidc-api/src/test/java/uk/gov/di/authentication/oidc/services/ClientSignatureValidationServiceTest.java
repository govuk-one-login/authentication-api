package uk.gov.di.authentication.oidc.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.Nonce;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.exceptions.ClientSignatureValidationException;
import uk.gov.di.orchestration.shared.services.ClientSignatureValidationService;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.List;

import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ClientSignatureValidationServiceTest {

    private static final String REDIRECT_URI = "https://localhost:8080";
    private static final ClientID CLIENT_ID = new ClientID("test-id");
    private static final URI OIDC_BASE_URI = URI.create("https://localhost");
    private static final URI TOKEN_URI = URI.create("https://localhost/token");
    private static final URI AUTHORIZE_URI = URI.create("https://localhost/authorize");

    private final OidcAPI oidcApi = mock(OidcAPI.class);
    private ClientSignatureValidationService clientSignatureValidationService;

    @BeforeEach
    void setup() {
        when(oidcApi.baseURI()).thenReturn(OIDC_BASE_URI);
        clientSignatureValidationService = new ClientSignatureValidationService(oidcApi);
    }

    @Test
    void shouldSuccessfullyReturnWhenValidatingValidSignedJWT() {
        var keyPair = generateKeyPair();
        var signedJWT = generateSignedJWT(keyPair.getPrivate());
        var client = generatClientRegistry(keyPair.getPublic());
        assertDoesNotThrow(() -> clientSignatureValidationService.validate(signedJWT, client));
    }

    @Test
    void shouldSuccessfullyReturnWhenValidatingValidPrivateKeyJWT() {
        var keyPair = generateKeyPair();
        var privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
        var client = generatClientRegistry(keyPair.getPublic());
        assertDoesNotThrow(
                () ->
                        clientSignatureValidationService.validateTokenClientAssertion(
                                privateKeyJWT, client));
    }

    @Test
    void shouldThrowExceptionWhenValidatingInvalidSignedJWT() {
        var keyPair1 = generateKeyPair();
        var keyPair2 = generateKeyPair();
        var signedJWT = generateSignedJWT(keyPair1.getPrivate());
        var client = generatClientRegistry(keyPair2.getPublic());
        assertThrows(
                ClientSignatureValidationException.class,
                () -> clientSignatureValidationService.validate(signedJWT, client));
    }

    @Test
    void shouldThrowExceptionWhenValidatingInvalidPrivateKeyJWT() {
        var keyPair1 = generateKeyPair();
        var keyPair2 = generateKeyPair();
        var privateKeyJWT = generatePrivateKeyJWT(keyPair1.getPrivate());
        var client = generatClientRegistry(keyPair2.getPublic());
        assertThrows(
                ClientSignatureValidationException.class,
                () ->
                        clientSignatureValidationService.validateTokenClientAssertion(
                                privateKeyJWT, client));
    }

    private static SignedJWT generateSignedJWT(PrivateKey privateKey) {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", "openid")
                        .claim("nonce", new Nonce().getValue())
                        .claim("state", new State().toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("vtr", List.of("P0.Cl"))
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var jwsHeader = new JWSHeader(RS256);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        var signer = new RSASSASigner(privateKey);
        try {
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        return signedJWT;
    }

    private static PrivateKeyJWT generatePrivateKeyJWT(PrivateKey privateKey) {
        try {
            return new PrivateKeyJWT(
                    new ClientID(CLIENT_ID), TOKEN_URI, JWSAlgorithm.RS256, privateKey, null, null);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    private static KeyPair generateKeyPair() {
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(KeyType.RSA.getValue());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return keyPairGenerator.generateKeyPair();
    }

    private static ClientRegistry generatClientRegistry(PublicKey publicKey) {
        var encodedPublicKey = Base64.getMimeEncoder().encodeToString(publicKey.getEncoded());
        return new ClientRegistry()
                .withClientID(CLIENT_ID.getValue())
                .withPublicKey(encodedPublicKey);
    }
}
