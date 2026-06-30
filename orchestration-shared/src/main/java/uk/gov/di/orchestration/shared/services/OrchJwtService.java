package uk.gov.di.orchestration.shared.services;

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
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.orchestration.shared.exceptions.InvalidJWEException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.JWT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class OrchJwtService {
    private static final Logger LOG = LogManager.getLogger(OrchJwtService.class);
    private static final JWSAlgorithm SIGNING_ALGORITHM = JWSAlgorithm.ES256;

    private final KmsConnectionService kmsConnectionService;
    private final JwksService jwksService;

    public OrchJwtService(ConfigurationService configurationService) {
        this(
                new KmsConnectionService(configurationService),
                new JwksService(
                        configurationService, new KmsConnectionService(configurationService)));
    }

    public OrchJwtService(KmsConnectionService kmsConnectionService, JwksService jwksService) {
        this.kmsConnectionService = kmsConnectionService;
        this.jwksService = jwksService;
    }

    public EncryptedJWT signAndEncryptJWT(
            JWTClaimsSet jwtClaimsSet, String signingKeyAlias, RSAPublicKey publicEncryptionKey) {
        if (jwtClaimsSet.getJWTID() != null) {
            attachLogFieldToLogs(JWT_ID, jwtClaimsSet.getJWTID());
        }
        LOG.info("Generating signed and encrypted JWT");
        var signingKey = jwksService.getPublicJWKWithKeyId(signingKeyAlias);
        var jwsHeader =
                new JWSHeader.Builder(SIGNING_ALGORITHM).keyID(signingKey.getKeyID()).build();

        var encodedHeader = jwsHeader.toBase64URL();
        var encodedClaims = Base64URL.encode(jwtClaimsSet.toString());
        var message = encodedHeader + "." + encodedClaims;

        var signRequestBuilder =
                SignRequest.builder()
                        .keyId(signingKeyAlias)
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256);

        SignRequest signRequest =
                isMessageHashSignRequired(message)
                        ? signRequestBuilder
                                .message(SdkBytes.fromByteArray(getMessageHashDigest(message)))
                                .messageType(MessageType.DIGEST)
                                .build()
                        : signRequestBuilder
                                .message(
                                        SdkBytes.fromByteArray(
                                                message.getBytes(StandardCharsets.UTF_8)))
                                .messageType(MessageType.RAW)
                                .build();
        try {
            LOG.info("Signing request JWT");
            var signResult = kmsConnectionService.sign(signRequest);
            LOG.info("Request JWT has been signed successfully");
            var signature =
                    Base64URL.encode(
                                    ECDSA.transcodeSignatureToConcat(
                                            signResult.signature().asByteArray(),
                                            ECDSA.getSignatureByteArrayLength(SIGNING_ALGORITHM)))
                            .toString();
            return encryptJWT(SignedJWT.parse(message + "." + signature), publicEncryptionKey);
        } catch (ParseException | JOSEException e) {
            LOG.error("Error when generating SignedJWT", e);
            throw new InvalidJWEException("Error when generating SignedJWT", e);
        }
    }

    private EncryptedJWT encryptJWT(SignedJWT signedJWT, RSAPublicKey publicEncryptionKey) {
        try {
            LOG.info("Encrypting SignedJWT");
            var jweObject =
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
            throw new InvalidJWEException("Error when encrypting SignedJWT", e);
        } catch (ParseException e) {
            LOG.error("Error when parsing JWE object to EncryptedJWT", e);
            throw new InvalidJWEException("Error when parsing JWE object to EncryptedJWT", e);
        }
    }

    private boolean isMessageHashSignRequired(String jwtMessage) {
        return jwtMessage.getBytes(StandardCharsets.UTF_8).length >= 4096;
    }

    private byte[] getMessageHashDigest(String jwtMessage) {
        byte[] signingInputHash;
        try {
            signingInputHash =
                    MessageDigest.getInstance("SHA-256")
                            .digest(jwtMessage.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage());
        }
        return signingInputHash;
    }
}
