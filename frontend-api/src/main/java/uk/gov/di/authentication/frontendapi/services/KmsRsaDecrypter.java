package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.util.Base64URL;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.IncorrectKeyException;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import javax.crypto.spec.SecretKeySpec;

import java.util.Objects;
import java.util.Set;

import static com.nimbusds.jose.JWEAlgorithm.RSA_OAEP_256;
import static software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256;

public class KmsRsaDecrypter implements JWEDecrypter {
    private static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS = Set.of(JWEAlgorithm.RSA_OAEP_256);
    private static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS =
            Set.of(EncryptionMethod.A256GCM);
    private static final Logger LOG = LogManager.getLogger(KmsRsaDecrypter.class);

    private final ConfigurationService configService;
    private final KmsConnectionService kmsConnectionService;
    private final JWEJCAContext jwejcaContext = new JWEJCAContext();

    public KmsRsaDecrypter(ConfigurationService configService) {
        this(configService, new KmsConnectionService(configService));
    }

    public KmsRsaDecrypter(
            ConfigurationService configService, KmsConnectionService kmsConnectionService) {
        this.configService = configService;
        this.kmsConnectionService = kmsConnectionService;
    }

    @Override
    public byte[] decrypt(
            JWEHeader header,
            Base64URL encryptedKey,
            Base64URL iv,
            Base64URL cipherText,
            Base64URL authTag,
            byte[] aad)
            throws JOSEException {
        if (Objects.isNull(encryptedKey)) {
            throw new JOSEException("Missing JWE encrypted key");
        }

        if (Objects.isNull(iv)) {
            throw new JOSEException("Missing JWE initialization vector (IV)");
        }

        if (Objects.isNull(authTag)) {
            throw new JOSEException("Missing JWE authentication tag");
        }

        JWEAlgorithm alg = header.getAlgorithm();

        if (!SUPPORTED_ALGORITHMS.contains(alg)) {
            throw new JOSEException(
                    AlgorithmSupportMessage.unsupportedJWEAlgorithm(alg, supportedJWEAlgorithms()));
        }

        var primaryKeyAlias = configService.getAuthEncryptionKeyPrimaryAlias();
        var secondaryKeyAlias = configService.getAuthEncryptionKeySecondaryAlias();

        // During a key rotation we might receive JWTs encrypted with either the old or new key.
        DecryptResponse decryptResponse;
        try {
            decryptResponse = makeDecryptRequest(encryptedKey, primaryKeyAlias);
        } catch (IncorrectKeyException e) {
            if (secondaryKeyAlias.isPresent()) {
                LOG.debug("Primary key is incorrect, trying secondary key");
                decryptResponse = makeDecryptRequest(encryptedKey, secondaryKeyAlias.get());
            } else {
                throw e;
            }
        }

        var contentEncryptionKey =
                new SecretKeySpec(decryptResponse.plaintext().asByteArray(), "AES");

        return ContentCryptoProvider.decrypt(
                header, encryptedKey, iv, cipherText, authTag, contentEncryptionKey, jwejcaContext);
    }

    private DecryptResponse makeDecryptRequest(Base64URL encryptedKey, String keyAlias) {
        var decryptRequest =
                DecryptRequest.builder()
                        .ciphertextBlob(SdkBytes.fromByteArray(encryptedKey.decode()))
                        .encryptionAlgorithm(RSAES_OAEP_SHA_256)
                        .keyId(keyAlias)
                        .build();

        return kmsConnectionService.decrypt(decryptRequest);
    }

    @Override
    public Set<JWEAlgorithm> supportedJWEAlgorithms() {
        return Set.of(RSA_OAEP_256);
    }

    @Override
    public Set<EncryptionMethod> supportedEncryptionMethods() {
        return SUPPORTED_ENCRYPTION_METHODS;
    }

    @Override
    public JWEJCAContext getJCAContext() {
        return jwejcaContext;
    }
}
