package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.exceptions.JarValidationException;
import uk.gov.di.authentication.shared.configuration.OauthClientConfig;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

public class JarValidationService {
    private static final Logger LOG = LogManager.getLogger(JarValidationService.class);

    private final ConfigurationService configService;
    private final JWEDecrypter jweDecrypter;
    private final Json objectMapper = SerializationService.getInstance();

    public JarValidationService(ConfigurationService configService) {
        this.configService = configService;
        if ("local".equals(configService.getEnvironment())) {
            this.jweDecrypter =
                    new RSADecrypter(parseRSAKey(configService.getAuthEncryptionKeyLocal()));
        } else {
            this.jweDecrypter = new KmsRsaDecrypter(configService);
        }
    }

    public JWTClaimsSet parseAndValidateJar(String jar, String clientId)
            throws JarValidationException {
        var jwt = decryptJar(jar);
        // TODO: check where we attach client id etc. to logs
        var clientConfig = getClientConfig(clientId);
        validateSignature(jwt, clientConfig);
        return getValidatedClaimSet(jwt, clientConfig);
    }

    private SignedJWT decryptJar(String jar) throws JarValidationException {
        try {
            var jwe = JWEObject.parse(jar);
            jwe.decrypt(jweDecrypter);
            return jwe.getPayload().toSignedJWT();
        } catch (JOSEException | ParseException e) {
            LOG.error("Failed to decrypt the JWE", e);
            throw new JarValidationException(
                    OAuth2Error.INVALID_REQUEST_OBJECT.setDescription(
                            "Failed to decrypt the contents of the JAR"));
        }
    }

    private OauthClientConfig getClientConfig(String clientId) throws JarValidationException {
        var clientConfigs = configService.getOauthClientConfig();
        if (!clientConfigs.containsKey(clientId)) {
            LOG.error("Unknown client id: {}", clientId);
            throw new JarValidationException(
                    OAuth2Error.INVALID_CLIENT.setDescription("Unknown client id was provided"));
        }
        return clientConfigs.get(clientId);
    }

    private void validateSignature(SignedJWT signedJWT, OauthClientConfig clientConfig)
            throws JarValidationException {
        try {
            var algorithm = signedJWT.getHeader().getAlgorithm();
            if (algorithm != JWSAlgorithm.ES256) {
                LOG.error(
                        "jwt signing algorithm {} does not match expected signing algorithm ES256",
                        algorithm);
                throw new JarValidationException(
                        OAuth2Error.INVALID_REQUEST_OBJECT.setDescription(
                                "Signing algorithm used does not match required algorithm"));
            }

            var verifier = new ECDSAVerifier(parseECKey(clientConfig.publicSigningKey()));

            if (!signedJWT.verify(verifier)) {
                LOG.error("JWT signature validation failed");
                throw new JarValidationException(
                        OAuth2Error.INVALID_REQUEST_OBJECT.setDescription(
                                "JWT signature validation failed"));
            }
        } catch (JOSEException e) {
            LOG.error("Failed to parse JWT when attempting signature validation", e);
            throw new JarValidationException(
                    OAuth2Error.INVALID_REQUEST_OBJECT.setDescription(
                            "Failed to parse JWT when attempting signature validation"));
        }
    }

    private JWTClaimsSet getValidatedClaimSet(SignedJWT signedJWT, OauthClientConfig clientConfig)
            throws JarValidationException {
        var audience = configService.getAuthAudience();

        var requiredClaims =
                new HashSet<>(
                        Set.of(
                                JWTClaimNames.EXPIRATION_TIME,
                                JWTClaimNames.NOT_BEFORE,
                                JWTClaimNames.ISSUED_AT));

        var verifier =
                new DefaultJWTClaimsVerifier<>(
                        audience.toString(),
                        new JWTClaimsSet.Builder()
                                .issuer(clientConfig.clientId())
                                .claim("client_id", clientConfig.clientId())
                                // TODO: Add response_type to JAR
                                // .claim("response_type", "code")
                                .build(),
                        requiredClaims);

        try {
            var claimsSet = signedJWT.getJWTClaimsSet();
            verifier.verify(claimsSet, null);

            validateMaxAllowedJarTtl(claimsSet);
            validateRedirectUri(claimsSet, clientConfig);

            return claimsSet;
        } catch (BadJWTException | ParseException e) {
            LOG.error("Claim set validation failed", e);
            throw new JarValidationException(
                    OAuth2Error.INVALID_GRANT.setDescription("Claim set validation failed"), e);
        }
    }

    private void validateMaxAllowedJarTtl(JWTClaimsSet claimsSet) throws JarValidationException {
        var maximumExpirationTime =
                Instant.now().plusSeconds(configService.getMaxJarTimeToLiveSeconds());
        var expirationTime = claimsSet.getExpirationTime().toInstant();

        if (expirationTime.isAfter(maximumExpirationTime)) {
            LOG.error("Client JWT expiry date is too far in the future");
            throw new JarValidationException(
                    OAuth2Error.INVALID_GRANT.setDescription(
                            "The client JWT expiry date has surpassed the maximum allowed ttl value"));
        }
    }

    private void validateRedirectUri(JWTClaimsSet claimsSet, OauthClientConfig clientConfig)
            throws JarValidationException {
        try {
            var redirectUri = claimsSet.getURIClaim("redirect_uri");

            if (redirectUri == null
                    || !clientConfig.redirectUris().contains(redirectUri.toString())) {
                LOG.error("Invalid redirect_uri claim provided for client");
                throw new JarValidationException(
                        OAuth2Error.INVALID_GRANT.setDescription(
                                "Invalid redirect_uri claim provided for configured client"));
            }
        } catch (ParseException e) {
            LOG.error(
                    "Failed to parse JWT claim set in order to access to the redirect_uri claim",
                    e);
            throw new JarValidationException(
                    OAuth2Error.INVALID_REQUEST_OBJECT.setDescription(
                            "Failed to parse JWT claim set in order to access redirect_uri claim"));
        }
    }

    private RSAPrivateKey parseRSAKey(String keyString) {
        try {
            var keySpec = new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(keyString));
            return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private ECPublicKey parseECKey(String keyString) throws JarValidationException {
        try {
            var keySpec = new X509EncodedKeySpec(Base64.getMimeDecoder().decode(keyString));
            return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            LOG.error("Could not parse public encryption key", e);
            throw new JarValidationException(OAuth2Error.SERVER_ERROR, e);
        }
    }
}
