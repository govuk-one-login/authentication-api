package uk.gov.di.orchestration.shared.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.utils.KeyPairUtils.generateRsaKeyPair;

class OrchJwtServiceTest {
    private static final String SIGNING_KEY_ID = "test-key-id";
    private static final String SIGNING_KEY_ALIAS = "test-key-alias";
    private static final String LONG_CLAIM = "1".repeat(5000);
    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);
    private final JwksService jwksService = mock(JwksService.class);
    private OrchJwtService orchJwtService;
    private ECKey ecSigningKey;
    private PrivateKey privateEncKey;
    private RSAPublicKey publicEncKey;

    @BeforeEach
    void setUp() throws Exception {
        ecSigningKey =
                new ECKeyGenerator(Curve.P_256)
                        .keyID(SIGNING_KEY_ID)
                        .algorithm(JWSAlgorithm.ES256)
                        .generate();
        when(jwksService.getPublicJWKWithKeyId(SIGNING_KEY_ALIAS))
                .thenReturn(ecSigningKey.toPublicJWK());
        var keyPair = generateRsaKeyPair();
        privateEncKey = keyPair.getPrivate();
        publicEncKey = (RSAPublicKey) keyPair.getPublic();

        orchJwtService = new OrchJwtService(kmsConnectionService, jwksService);
    }

    @Test
    void shouldConstructASignedAndEncryptedRequestJWT() throws Exception {
        var claim1Value = "JWT claim 1";
        var jwtClaimsSet = new JWTClaimsSet.Builder().claim("claim1", claim1Value).build();
        var jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(SIGNING_KEY_ID).build();
        var expectedMessage =
                jwsHeader.toBase64URL() + "." + Base64URL.encode(jwtClaimsSet.toString());
        mockKmsSigning(ecSigningKey, jwtClaimsSet);

        var encryptedJWT =
                orchJwtService.signAndEncryptJWT(jwtClaimsSet, SIGNING_KEY_ALIAS, publicEncKey);

        var signedJWTResponse = decryptJWT(encryptedJWT);
        var signRequestCaptor = ArgumentCaptor.forClass(SignRequest.class);
        assertThat(signedJWTResponse.getJWTClaimsSet().getClaim("claim1"), equalTo(claim1Value));
        verify(kmsConnectionService).sign(signRequestCaptor.capture());
        assertThat(
                SdkBytes.fromByteArray(expectedMessage.getBytes(StandardCharsets.UTF_8)),
                equalTo(signRequestCaptor.getValue().message()));
        assertThat(MessageType.RAW, equalTo(signRequestCaptor.getValue().messageType()));
    }

    @Test
    void shouldUseAHashDigestWhenMessageSizeIsMoreThan4095() throws Exception {
        var claim1Value = "JWT claim 1";
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .claim("claim1", claim1Value)
                        .claim("state", LONG_CLAIM)
                        .build();
        var jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(SIGNING_KEY_ID).build();
        var expectedMessage =
                jwsHeader.toBase64URL() + "." + Base64URL.encode(jwtClaimsSet.toString());
        mockKmsSigning(ecSigningKey, jwtClaimsSet);

        var encryptedJWT =
                orchJwtService.signAndEncryptJWT(jwtClaimsSet, SIGNING_KEY_ALIAS, publicEncKey);

        var signRequestCaptor = ArgumentCaptor.forClass(SignRequest.class);
        var signedJWTResponse = decryptJWT(encryptedJWT);
        assertThat(signedJWTResponse.getJWTClaimsSet().getClaim("claim1"), equalTo(claim1Value));
        assertThat(signedJWTResponse.getJWTClaimsSet().getClaim("state"), equalTo(LONG_CLAIM));
        signedJWTResponse.verify(new ECDSAVerifier(ecSigningKey.toECPublicKey()));
        verify(kmsConnectionService).sign(signRequestCaptor.capture());
        assertThat(
                getHashSdkBytes(expectedMessage), equalTo(signRequestCaptor.getValue().message()));
        assertThat(MessageType.DIGEST, equalTo(signRequestCaptor.getValue().messageType()));
    }

    private SignedJWT decryptJWT(EncryptedJWT encryptedJWT) throws JOSEException {
        encryptedJWT.decrypt(new RSADecrypter(privateEncKey));
        return encryptedJWT.getPayload().toSignedJWT();
    }

    private SdkBytes getHashSdkBytes(String jwtMessage) {
        byte[] signingInputHash;
        try {
            signingInputHash =
                    MessageDigest.getInstance("SHA-256")
                            .digest(jwtMessage.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage());
        }
        return SdkBytes.fromByteArray(signingInputHash);
    }

    private void mockKmsSigning(ECKey ecSigningKey, JWTClaimsSet jwtClaimsSet) throws Exception {
        var ecdsaSigner = new ECDSASigner(ecSigningKey);
        var jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(SIGNING_KEY_ID).build();
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        signedJWT.sign(ecdsaSigner);
        byte[] signatureToDER = ECDSA.transcodeSignatureToDER(signedJWT.getSignature().decode());
        var signResult =
                SignResponse.builder()
                        .signature(SdkBytes.fromByteArray(signatureToDER))
                        .keyId(SIGNING_KEY_ID)
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .build();
        when(kmsConnectionService.sign(any(SignRequest.class))).thenReturn(signResult);
    }
}
