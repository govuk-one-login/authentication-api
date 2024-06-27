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
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

import static com.nimbusds.jose.crypto.impl.ECDSA.getSignatureByteArrayLength;

public class JwtService {
    private static final Logger LOG = LogManager.getLogger(JwtService.class);
    private final KmsConnectionService kmsConnectionService;

    public JwtService(KmsConnectionService kmsConnectionService) {
        this.kmsConnectionService = kmsConnectionService;
    }

    public SignedJWT signJWT(
            JWSAlgorithm signingAlgorithm, JWTClaimsSet jwtClaims, String keyAlias) {
        LOG.info("Creating signed JWT");
        Base64URL encodedHeader = new JWSHeader(signingAlgorithm).toBase64URL();
        Base64URL encodedClaims = Base64URL.encode(jwtClaims.toString());
        String message = encodedHeader + "." + encodedClaims;
        SignRequest signRequest =
                SignRequest.builder()
                        .message(SdkBytes.fromByteArray(message.getBytes(StandardCharsets.UTF_8)))
                        .keyId(keyAlias)
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .build();
        try {
            LOG.info("Signing JWT");
            SignResponse signResult = kmsConnectionService.sign(signRequest);
            String signature =
                    Base64URL.encode(
                                    ECDSA.transcodeSignatureToConcat(
                                            signResult.signature().asByteArray(),
                                            getSignatureByteArrayLength(signingAlgorithm)))
                            .toString();
            LOG.info("JWT has been signed successfully");
            return SignedJWT.parse(message + "." + signature);
        } catch (KmsException e) {
            LOG.error("KMS error when signing JWT", e);
            throw new RuntimeException(e);
        } catch (ParseException | JOSEException e) {
            LOG.error("Failed to sign JWT", e);
            throw new RuntimeException(e);
        }
    }

    public EncryptedJWT encryptJWT(SignedJWT signedJWT, RSAPublicKey publicEncryptionKey) {
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
            throw new RuntimeException(e);
        } catch (ParseException e) {
            LOG.error("Error when parsing JWE object to EncryptedJWT", e);
            throw new RuntimeException(e);
        }
    }
}
