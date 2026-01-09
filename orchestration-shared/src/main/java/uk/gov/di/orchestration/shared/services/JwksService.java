package uk.gov.di.orchestration.shared.services;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import uk.gov.di.orchestration.shared.helpers.CryptoProviderHelper;
import uk.gov.di.orchestration.shared.utils.JwksUtils;

import java.net.URL;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static com.nimbusds.jose.jwk.Curve.P_256;
import static software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec.ECDSA_SHA_256;
import static uk.gov.di.orchestration.shared.helpers.HashHelper.hashSha256String;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class JwksService {
    private final ConfigurationService configurationService;
    private final KmsConnectionService kmsConnectionService;
    private static final Map<String, JWK> KEY_CACHE = new HashMap<>();
    private static final Logger LOG = LogManager.getLogger(JwksService.class);

    public JwksService(
            ConfigurationService configurationService, KmsConnectionService kmsConnectionService) {
        this.configurationService = configurationService;
        this.kmsConnectionService = kmsConnectionService;
    }

    public JWK getPublicTokenJwkWithOpaqueId() {
        LOG.info("Retrieving EC public key");
        return getPublicJWKWithKeyId(configurationService.getExternalTokenSigningKeyAlias());
    }

    public JWK getPublicTokenRsaJwkWithOpaqueId() {
        LOG.info("Retrieving RSA public key");
        return getPublicJWKWithKeyId(configurationService.getExternalTokenSigningKeyRsaAlias());
    }

    public JWK getNextPublicTokenJwkWithOpaqueId() {
        LOG.info("Retrieving next EC public key");
        return getPublicJWKWithKeyId(configurationService.getNextExternalTokenSigningKeyAlias());
    }

    public JWK getNextPublicTokenRsaJwkWithOpaqueId() {
        LOG.info("Retrieving next RSA public key");
        return getPublicJWKWithKeyId(configurationService.getNextExternalTokenSigningKeyRsaAlias());
    }

    public JWK getPublicDocAppSigningJwkWithOpaqueId() {
        LOG.info("Retrieving Doc App public key");
        return getPublicJWKWithKeyId(configurationService.getDocAppTokenSigningKeyAlias());
    }

    public JWK getPublicStorageTokenJwkWithOpaqueId() {
        LOG.info("Retrieving storage token public key");
        return getPublicJWKWithKeyId(configurationService.getStorageTokenSigningKeyAlias());
    }

    public JWK getPublicIpvTokenJwkWithOpaqueId() {
        LOG.info("Retrieving IPV token public key");
        return getPublicJWKWithKeyId(configurationService.getIPVTokenSigningKeyAlias());
    }

    public JWK retrieveJwkFromURLWithKeyId(URL url, String keyId) throws KeySourceException {
        return JwksUtils.retrieveJwkFromURLWithKeyId(url, keyId);
    }

    private JWK getPublicJWKWithKeyId(String keyId) {
        var jwk =
                segmentedFunctionCall(
                        "createJwk", () -> KEY_CACHE.computeIfAbsent(keyId, this::createJwk));

        return segmentedFunctionCall(
                "parseJwk",
                () -> {
                    try {
                        return JWK.parse(jwk.toString());
                    } catch (java.text.ParseException e) {
                        LOG.error("Error parsing the public key to JWK", e);
                        throw new RuntimeException(e);
                    }
                });
    }

    private JWK createJwk(String keyId) {
        var getPublicKeyRequest = GetPublicKeyRequest.builder().keyId(keyId).build();
        var publicKeyResponse = kmsConnectionService.getPublicKey(getPublicKeyRequest);

        PublicKey publicKey = createPublicKey(publicKeyResponse);

        if (publicKeyResponse.signingAlgorithms().contains(ECDSA_SHA_256)) {
            return new ECKey.Builder(P_256, (ECPublicKey) publicKey)
                    .keyID(hashSha256String(publicKeyResponse.keyId()))
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(ES256)
                    .build();
        } else {
            return new RSAKey.Builder((RSAPublicKey) publicKey)
                    .keyID(hashSha256String(publicKeyResponse.keyId()))
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(RS256)
                    .build();
        }
    }

    private PublicKey createPublicKey(GetPublicKeyResponse publicKeyResponse) {
        SubjectPublicKeyInfo subjectKeyInfo =
                SubjectPublicKeyInfo.getInstance(publicKeyResponse.publicKey().asByteArray());

        try {
            return new JcaPEMKeyConverter()
                    .setProvider(CryptoProviderHelper.bouncyCastle())
                    .getPublicKey(subjectKeyInfo);
        } catch (PEMException e) {
            LOG.error("Error getting the PublicKey using the JcaPEMKeyConverter", e);
            throw new RuntimeException();
        }
    }
}
