package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.authentication.frontendapi.exceptions.JwtServiceException;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

public class JwtService {
    private static final Logger LOG = LogManager.getLogger(JwtService.class);
    private static final int ECDSA_P256_SIGNATURE_LENGTH = 64;
    private final KmsConnectionService kmsConnectionService;

    public JwtService(KmsConnectionService kmsConnectionService) {
        this.kmsConnectionService = kmsConnectionService;
    }

    public SignedJWT signJWT(JWTClaimsSet jwtClaims, String keyId) throws JwtServiceException {
        JWSHeader header =
                new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build();

        Base64URL encodedHeader = header.toBase64URL();
        Base64URL encodedClaims = jwtClaims.toPayload().toBase64URL();
        String signingInput = encodedHeader + "." + encodedClaims;

        SignResponse signResponse;
        try {
            SignRequest signRequest =
                    SignRequest.builder()
                            .keyId(keyId)
                            .message(
                                    SdkBytes.fromByteArray(
                                            signingInput.getBytes(StandardCharsets.UTF_8)))
                            .messageType(MessageType.RAW)
                            .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                            .build();

            signResponse = kmsConnectionService.sign(signRequest);
        } catch (SdkException e) {
            LOG.error("AWS SDK error when signing JWT", e);
            throw new JwtServiceException("AWS SDK error when signing JWT", e);
        }

        Base64URL signature;
        try {
            byte[] derSignature = signResponse.signature().asByteArray();
            byte[] joseSignature =
                    ECDSA.transcodeSignatureToConcat(derSignature, ECDSA_P256_SIGNATURE_LENGTH);
            signature = Base64URL.encode(joseSignature);
        } catch (JOSEException e) {
            LOG.error("Failed to transcode KMS signature from DER to JOSE format", e);
            throw new JwtServiceException("Failed to transcode signature", e);
        }

        try {
            return new SignedJWT(encodedHeader, encodedClaims, signature);
        } catch (ParseException e) {
            LOG.error("Failed to construct final SignedJWT object", e);
            throw new JwtServiceException("Failed to construct JWT", e);
        }
    }

    public EncryptedJWT encryptJWT(SignedJWT signedJWT, RSAPublicKey publicEncryptionKey)
            throws JwtServiceException {
        try {
            LOG.info("Encrypting SignedJWT");
            JWEObject jweObject =
                    new JWEObject(
                            new JWEHeader.Builder(
                                            JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                                    .contentType("JWT")
                                    .build(),
                            new Payload(signedJWT));
            jweObject.encrypt(new RSAEncrypter(publicEncryptionKey));
            LOG.info("SignedJWT has been successfully encrypted");
            return EncryptedJWT.parse(jweObject.serialize());
        } catch (JOSEException e) {
            LOG.error("Error when encrypting SignedJWT", e);
            throw new JwtServiceException(
                    String.format("JOSEException when encrypting JWT: \"%s\" ", e.getMessage()));
        } catch (ParseException e) {
            LOG.error("Error when parsing JWE object to EncryptedJWT", e);
            throw new JwtServiceException(
                    String.format("ParseException when encrypting JWT: \"%s\" ", e.getMessage()));
        }
    }
}
