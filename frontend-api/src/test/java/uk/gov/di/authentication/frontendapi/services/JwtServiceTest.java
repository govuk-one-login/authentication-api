package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.sharedtest.helper.KeyPairHelper;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.helpers.HashHelper.hashSha256String;

class JwtServiceTest {
    private static final Base64URL TEST_SIGNATURE =
            new Base64URL(
                    "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q");
    private static final String TEST_CLAIM_NAME = "sub";
    private static final String TEST_CLAIM_VALUE = "urn:some:user:identifier:rhbefhrbeqidnejrf";
    private static final JWTClaimsSet TEST_CLAIMS =
            new JWTClaimsSet.Builder().claim(TEST_CLAIM_NAME, TEST_CLAIM_VALUE).build();
    private static final JWSAlgorithm TEST_ALGORITHM = JWSAlgorithm.ES256;
    private static final String TEST_KEY_ID = "12345678";
    private static final Base64URL TEST_EXPECTED_HEADER =
            new JWSHeader.Builder(TEST_ALGORITHM)
                    .keyID(hashSha256String(TEST_KEY_ID))
                    .build()
                    .toBase64URL();
    private static final KeyPair TEST_KEY_PAIR = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
    private static SignedJWT testSignedJwt;
    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);
    private final JwtService jwtService = new JwtService(kmsConnectionService);

    @BeforeEach
    void testSetup() throws JOSEException, ParseException {
        byte[] signatureToDER = ECDSA.transcodeSignatureToDER(TEST_SIGNATURE.decode());
        when(kmsConnectionService.sign(any()))
                .thenReturn(
                        SignResponse.builder()
                                .signature(SdkBytes.fromByteArray(signatureToDER))
                                .build());

        when(kmsConnectionService.getPublicKey(any()))
                .thenReturn(GetPublicKeyResponse.builder().keyId(TEST_KEY_ID).build());

        testSignedJwt =
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
                        .keyId(TEST_KEY_ID)
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .build();
        SignedJWT signedJWT = jwtService.signJWT(TEST_ALGORITHM, TEST_CLAIMS, TEST_KEY_ID);
        verify(kmsConnectionService)
                .getPublicKey(GetPublicKeyRequest.builder().keyId(TEST_KEY_ID).build());
        verify(kmsConnectionService).sign(expectedSignRequest);
        assertEquals(TEST_EXPECTED_HEADER, signedJWT.getHeader().toBase64URL());
        assertEquals(TEST_SIGNATURE.toString(), signedJWT.getSignature().toString());
        assertEquals(TEST_CLAIM_VALUE, signedJWT.getJWTClaimsSet().getClaim(TEST_CLAIM_NAME));
        assertEquals(encodedClaims, signedJWT.getPayload().toBase64URL());
    }

    @Test
    void shouldEncryptJWTWithProvidedRsaKeyAndReturnJWE() throws JOSEException {
        var publicKey = (RSAPublicKey) TEST_KEY_PAIR.getPublic();
        var privateKey = (RSAPrivateKey) TEST_KEY_PAIR.getPrivate();
        EncryptedJWT encryptedJWT = jwtService.encryptJWT(testSignedJwt, publicKey);
        encryptedJWT.decrypt(new RSADecrypter(privateKey));
        assertEquals(
                encryptedJWT.getHeader().toString(),
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                        .contentType("JWT")
                        .build()
                        .toString());
        assertEquals(testSignedJwt.serialize(), encryptedJWT.getPayload().toString());
    }
}
