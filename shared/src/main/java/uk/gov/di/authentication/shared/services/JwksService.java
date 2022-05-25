package uk.gov.di.authentication.shared.services;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import uk.gov.di.authentication.shared.helpers.EnvironmentAwareCryptoProvider;

import java.io.IOException;
import java.net.URL;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

import static uk.gov.di.authentication.shared.helpers.HashHelper.hashSha256String;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class JwksService {

    private final ConfigurationService configurationService;
    private final KmsConnectionService kmsConnectionService;
    private static final Map<String, ECKey> KEY_CACHE = new HashMap<>();
    private static final Logger LOG = LogManager.getLogger(JwksService.class);

    public JwksService(
            ConfigurationService configurationService, KmsConnectionService kmsConnectionService) {
        this.configurationService = configurationService;
        this.kmsConnectionService = kmsConnectionService;
    }

    public JWK getPublicTokenJwkWithOpaqueId() {
        return getPublicJWKWithKeyId(configurationService.getTokenSigningKeyAlias());
    }

    public JWK getPublicDocAppSigningJwkWithOpaqueId() {
        return getPublicJWKWithKeyId(configurationService.getDocAppTokenSigningKeyAlias());
    }

    public JWKSet retrieveJwkSetFromURL(URL url) {
        try {
            LOG.info("Retrieving JWKSet with URL: {}", url);
            return JWKSet.load(url);
        } catch (IOException | ParseException e) {
            LOG.error("Unable to load JWKSet", e);
            throw new RuntimeException(e);
        }
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

    private ECKey createJwk(String keyId) {
        var getPublicKeyRequest = GetPublicKeyRequest.builder().keyId(keyId).build();
        var publicKeyResponse = kmsConnectionService.getPublicKey(getPublicKeyRequest);

        PublicKey publicKey = createPublicKey(publicKeyResponse);

        return new ECKey.Builder(Curve.P_256, (ECPublicKey) publicKey)
                .keyID(hashSha256String(publicKeyResponse.keyId()))
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(new Algorithm(JWSAlgorithm.ES256.getName()))
                .build();
    }

    private PublicKey createPublicKey(GetPublicKeyResponse publicKeyResponse) {
        SubjectPublicKeyInfo subjectKeyInfo =
                SubjectPublicKeyInfo.getInstance(publicKeyResponse.publicKey().asByteArray());

        try {
            return new JcaPEMKeyConverter()
                    .setProvider(EnvironmentAwareCryptoProvider.provider())
                    .getPublicKey(subjectKeyInfo);
        } catch (PEMException e) {
            LOG.error("Error getting the PublicKey using the JcaPEMKeyConverter", e);
            throw new RuntimeException();
        }
    }
}
