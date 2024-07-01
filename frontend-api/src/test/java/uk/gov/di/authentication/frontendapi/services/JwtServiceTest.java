package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class JwtServiceTest {
    private static final Base64URL TEST_SIGNATURE =
            new Base64URL(
                    "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q");
    private static final String TEST_CLAIM_NAME = "testClaim";
    private static final String TEST_CLAIM_VALUE = "helloThere";
    private static final JWTClaimsSet TEST_CLAIMS =
            new JWTClaimsSet.Builder().claim(TEST_CLAIM_NAME, TEST_CLAIM_VALUE).build();
    private static final JWSAlgorithm TEST_ALGORITHM = JWSAlgorithm.ES256;
    private static final String TEST_KEY_ALIAS = "someSigningKey";
    private static final Base64URL TEST_EXPECTED_HEADER =
            new JWSHeader(TEST_ALGORITHM).toBase64URL();
    private static final RSAKey TEST_KEY_PAIR_GENERATOR = generateTestKeyPair();
    private static SignedJWT TEST_SIGNED_JWT;
    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);
    private final JwtService jwtService = new JwtService(kmsConnectionService);

    private static RSAKey generateTestKeyPair() {
        try {
            return new RSAKeyGenerator(2048).generate();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    @BeforeEach
    void testSetup() throws JOSEException, ParseException {
        byte[] signatureToDER = ECDSA.transcodeSignatureToDER(TEST_SIGNATURE.decode());
        when(kmsConnectionService.sign(any()))
                .thenReturn(
                        SignResponse.builder()
                                .signature(SdkBytes.fromByteArray(signatureToDER))
                                .build());
        TEST_SIGNED_JWT =
                new SignedJWT(
                        TEST_EXPECTED_HEADER,
                        Base64URL.encode(TEST_CLAIMS.toString()),
                        TEST_SIGNATURE);
    }

    @Test
    void CallsKmsToGenerateSignatureAndReturnsJWS() throws ParseException {
        Base64URL encodedClaims = Base64URL.encode(TEST_CLAIMS.toString());
        SdkBytes expectedMessage =
                SdkBytes.fromByteArray(
                        (TEST_EXPECTED_HEADER + "." + encodedClaims)
                                .getBytes(StandardCharsets.UTF_8));
        SignRequest expectedSignRequest =
                SignRequest.builder()
                        .message(expectedMessage)
                        .keyId(TEST_KEY_ALIAS)
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .build();
        SignedJWT signedJWT = jwtService.signJWT(TEST_ALGORITHM, TEST_CLAIMS, TEST_KEY_ALIAS);
        verify(kmsConnectionService).sign(expectedSignRequest);
        assertEquals(TEST_EXPECTED_HEADER, signedJWT.getHeader().toBase64URL());
        assertEquals(TEST_SIGNATURE.toString(), signedJWT.getSignature().toString());
        assertEquals(TEST_CLAIM_VALUE, signedJWT.getJWTClaimsSet().getClaim(TEST_CLAIM_NAME));
        assertEquals(encodedClaims, signedJWT.getPayload().toBase64URL());
    }

    @Test
    void shouldEncryptJWTWithProvidedRsaKeyAndReturnJWE() throws JOSEException {
        RSAPublicKey publicKey = TEST_KEY_PAIR_GENERATOR.toRSAPublicKey();
        RSAPrivateKey privateKey = TEST_KEY_PAIR_GENERATOR.toRSAPrivateKey();
        EncryptedJWT encryptedJWT = jwtService.encryptJWT(TEST_SIGNED_JWT, publicKey);
        encryptedJWT.decrypt(new RSADecrypter(privateKey));
        assertEquals(
                encryptedJWT.getHeader().toString(),
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                        .contentType("JWT")
                        .build()
                        .toString());
        assertEquals(TEST_SIGNED_JWT.serialize(), encryptedJWT.getPayload().toString());
    }
}
