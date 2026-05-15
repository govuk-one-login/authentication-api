package uk.gov.di.accountmanagement.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.JwksService;
import uk.gov.di.authentication.shared.services.RemoteJwksService;

import java.text.ParseException;

public class TokenValidationService {

    private final JwksService jwksService;
    private final RemoteJwksService accessTokenJwksService;
    private final ConfigurationService configuration;
    private static final Logger LOG = LogManager.getLogger(TokenValidationService.class);

    public TokenValidationService(
            JwksService jwksService,
            RemoteJwksService accessTokenJwksService,
            ConfigurationService configuration) {
        this.jwksService = jwksService;
        this.accessTokenJwksService = accessTokenJwksService;
        this.configuration = configuration;
    }

    public boolean validateAccessTokenSignature(AccessToken accessToken) {
        String tokenValue = accessToken.getValue();
        try {
            var jwt = SignedJWT.parse(tokenValue);

            if (JWSAlgorithm.RS256 == jwt.getHeader().getAlgorithm()
                    && configuration.isRsaSigningAvailable()) {
                return jwt.verify(
                        new RSASSAVerifier(
                                accessTokenJwksService
                                        .retrieveJwkFromURLWithKeyId(jwt.getHeader().getKeyID())
                                        .toRSAKey()));
            } else {
                if (configuration.isTestSigningKeyEnabled()) {
                    var acceptanceTestKey = jwksService.getPublicTestTokenJwkWithOpaqueId();
                    boolean isValid = jwt.verify(new ECDSAVerifier(acceptanceTestKey.toECKey()));
                    if (isValid) {
                        LOG.info("Token signature validated using test key");
                        return isValid;
                    }
                }
                return jwt.verify(
                        new ECDSAVerifier(
                                accessTokenJwksService
                                        .retrieveJwkFromURLWithKeyId(jwt.getHeader().getKeyID())
                                        .toECKey()));
            }
        } catch (JOSEException | ParseException e) {
            LOG.warn("Unable to validate Signature of Token", e);
            return false;
        }
    }
}
