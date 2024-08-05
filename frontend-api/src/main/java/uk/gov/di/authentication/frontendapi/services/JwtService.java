package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
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
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.authentication.frontendapi.exceptions.JwtServiceException;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

import static com.nimbusds.jose.crypto.impl.ECDSA.getSignatureByteArrayLength;
import static uk.gov.di.authentication.shared.helpers.HashHelper.hashSha256String;

public class JwtService {
    private static final Logger LOG = LogManager.getLogger(JwtService.class);
    private final KmsConnectionService kmsConnectionService;

    public JwtService(KmsConnectionService kmsConnectionService) {
        this.kmsConnectionService = kmsConnectionService;
    }

    public SignedJWT signJWT(JWSAlgorithm signingAlgorithm, JWTClaimsSet jwtClaims, String keyId)
            throws JwtServiceException {
        LOG.info("Creating signed JWT");
        try {
            var signingKeyId =
                    kmsConnectionService
                            .getPublicKey(GetPublicKeyRequest.builder().keyId(keyId).build())
                            .keyId();

            var encodedHeader =
                    new JWSHeader.Builder(signingAlgorithm)
                            .keyID(hashSha256String(signingKeyId))
                            .build()
                            .toBase64URL();
            var encodedClaims = Base64URL.encode(jwtClaims.toString());
            var message = encodedHeader + "." + encodedClaims;
            SignRequest signRequest =
                    SignRequest.builder()
                            .message(
                                    SdkBytes.fromByteArray(
                                            message.getBytes(StandardCharsets.UTF_8)))
                            .keyId(keyId)
                            .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                            .build();

            LOG.info("Signing JWT");
            SignResponse signResult = kmsConnectionService.sign(signRequest);
            var signature = parseSignature(signResult.signature().asByteArray(), signingAlgorithm);
            SignedJWT signedJWT = SignedJWT.parse(message + "." + signature);
            LOG.info("JWT has been signed and parsed successfully");
            return signedJWT;
        } catch (KmsException e) {
            LOG.error("KMS error when signing JWT", e);
            throw new JwtServiceException(
                    String.format("KMS error when signing JWT: \"%s\" ", e.getMessage()));
        } catch (ParseException | JOSEException e) {
            LOG.error("Failed to sign JWT", e);
            throw new JwtServiceException(
                    String.format("Failed to sign JWT: \"%s\" ", e.getMessage()));
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

    private String parseSignature(byte[] signature, JWSAlgorithm signingAlgorithm)
            throws JOSEException {
        return Base64URL.encode(
                        ECDSA.transcodeSignatureToConcat(
                                signature, getSignatureByteArrayLength(signingAlgorithm)))
                .toString();
    }
}
