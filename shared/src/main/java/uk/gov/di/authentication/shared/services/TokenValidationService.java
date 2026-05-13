package uk.gov.di.authentication.shared.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;

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
        return isTokenSignatureValid(accessToken.getValue());
    }

    public boolean isTokenSignatureValid(String tokenValue) {
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
        } catch (JOSEException | java.text.ParseException e) {
            LOG.warn("Unable to validate Signature of Token", e);
            return false;
        }
    }

    public boolean validateRefreshTokenScopes(
            List<String> clientScopes, List<String> refreshTokenScopes) {
        if (!clientScopes.containsAll(refreshTokenScopes)) {
            LOG.warn("Scopes in Client Registry does not contain all scopes in Refresh Token");
            return false;
        }
        if (!refreshTokenScopes.contains(OIDCScopeValue.OFFLINE_ACCESS.getValue())) {
            LOG.warn("Scopes in Refresh Token does not contain OFFLINE_ACCESS scope");
            return false;
        }
        return true;
    }
}
