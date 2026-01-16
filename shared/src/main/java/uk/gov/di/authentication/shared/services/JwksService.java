package uk.gov.di.authentication.shared.services;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import uk.gov.di.authentication.shared.exceptions.JwksServiceException;
import uk.gov.di.authentication.shared.helpers.CryptoProviderHelper;

import java.net.MalformedURLException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static com.nimbusds.jose.jwk.Curve.P_256;
import static software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec.ECDSA_SHA_256;
import static uk.gov.di.authentication.shared.helpers.HashHelper.hashSha256String;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class JwksService {

    private final ConfigurationService configurationService;
    private final KmsConnectionService kmsConnectionService;
    private static final Map<String, JWK> KEY_CACHE = new HashMap<>();
    private static final Logger LOG = LogManager.getLogger(JwksService.class);
    private final JWKSource<SecurityContext> jwkSource;

    public JwksService(
            ConfigurationService configurationService, KmsConnectionService kmsConnectionService) {
        this(configurationService, kmsConnectionService, false);
    }

    public JwksService(
            ConfigurationService configurationService,
            KmsConnectionService kmsConnectionService,
            boolean useAccessTokenJwksUrl) {
        this.configurationService = configurationService;
        this.kmsConnectionService = kmsConnectionService;
        try {
            int millisecondTimeout = 25000;
            this.jwkSource =
                    useAccessTokenJwksUrl
                            ? JWKSourceBuilder.create(
                                            configurationService.getAccessTokenJwksUrl(),
                                            new DefaultResourceRetriever(
                                                    millisecondTimeout, millisecondTimeout))
                                    .retrying(true)
                                    .refreshAheadCache(false)
                                    .cache(true)
                                    .rateLimited(false)
                                    .build()
                            : null;
        } catch (Exception e) {
            LOG.error("Error while initializing JwksService", e);
            throw new JwksServiceException("Failed to initialize JwksService");
        }
    }

    public JwksService(
            ConfigurationService configurationService,
            KmsConnectionService kmsConnectionService,
            JWKSource<SecurityContext> jwkSource) {
        this.configurationService = configurationService;
        this.kmsConnectionService = kmsConnectionService;
        this.jwkSource = jwkSource;
    }

    public JWK getPublicTokenJwkWithOpaqueId(String keyId) throws MalformedURLException {
        LOG.info("Retrieving EC public key");
        return configurationService.useAccessTokenJwksEndpoint()
                ? retrieveJwkFromURLWithKeyId(keyId)
                : getPublicJWKWithKeyId(configurationService.getTokenSigningKeyAlias());
    }

    public JWK getPublicTokenRsaJwkWithOpaqueId() {
        LOG.info("Retrieving RSA public key");
        return getPublicJWKWithKeyId(configurationService.getTokenSigningKeyRsaAlias());
    }

    public JWK getPublicTestTokenJwkWithOpaqueId() {
        LOG.info("Retrieving EC public key for acceptance tests");
        String testTokenSigningKeyAlias = configurationService.getTestTokenSigningKeyAlias();

        if (testTokenSigningKeyAlias == null) {
            return null;
        }

        return getPublicJWKWithKeyId(testTokenSigningKeyAlias);
    }

    public JWK getPublicDocAppSigningJwkWithOpaqueId() {
        LOG.info("Retrieving Doc App public key");
        return getPublicJWKWithKeyId(configurationService.getDocAppTokenSigningKeyAlias());
    }

    public JWK getPublicMfaResetStorageTokenJwkWithOpaqueId() {
        LOG.info("Retrieving storage token public key");
        return getPublicJWKWithKeyId(configurationService.getMfaResetStorageTokenSigningKeyAlias());
    }

    public JWK getPublicMfaResetJarJwkWithOpaqueId() {
        LOG.info("Retrieving MFA Reset JAR primary signing public key");
        return getPublicJWKWithKeyId(configurationService.getMfaResetJarSigningKeyAlias());
    }

    public JWK getPublicMfaResetJarDeprecatedJwkWithOpaqueId() {
        String deprecatedKeyAlias = configurationService.getMfaResetJarDeprecatedSigningKeyAlias();

        if (deprecatedKeyAlias == null) {
            return null;
        }

        LOG.info("Retrieving MFA Reset JAR deprecated signing public key");
        return getPublicJWKWithKeyId(deprecatedKeyAlias);
    }

    public JWK retrieveJwkFromURLWithKeyId(String keyId) {
        JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().keyID(keyId).build());
        try {
            LOG.info("Retrieving JWKSet with from URL");
            return jwkSource.get(selector, null).stream()
                    .findFirst()
                    .orElseThrow(() -> new KeySourceException("No key found with given keyID"));
        } catch (KeySourceException e) {
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
