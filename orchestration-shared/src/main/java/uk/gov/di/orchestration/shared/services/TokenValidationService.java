package uk.gov.di.orchestration.shared.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.helpers.NowHelper;

import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public class TokenValidationService {

    private final JwksService jwksService;
    private final ConfigurationService configuration;
    private static final Logger LOG = LogManager.getLogger(TokenValidationService.class);

    public TokenValidationService(JwksService jwksService, ConfigurationService configuration) {
        this.jwksService = jwksService;
        this.configuration = configuration;
    }

    public boolean validateRefreshTokenSignatureAndExpiry(RefreshToken refreshToken) {
        if (!isTokenSignatureValid(refreshToken.getValue())) {
            LOG.warn("Refresh token has invalid signature");
            return false;
        }
        if (hasTokenExpired(refreshToken.getValue())) {
            LOG.warn("Refresh token has expired");
            return false;
        }
        return true;
    }

    private boolean hasTokenExpired(String tokenValue) {
        try {
            JWTClaimsSet claimsSet = SignedJWT.parse(tokenValue).getJWTClaimsSet();
            Date currentDateTime = NowHelper.now();
            if (DateUtils.isBefore(claimsSet.getExpirationTime(), currentDateTime, 0)) {
                return true;
            }
        } catch (java.text.ParseException e) {
            LOG.warn("Unable to parse token when checking if expired", e);
            return true;
        }
        return false;
    }

    public boolean isTokenSignatureValid(String tokenValue) {
        try {
            var jwt = SignedJWT.parse(tokenValue);

            if (JWSAlgorithm.RS256 == jwt.getHeader().getAlgorithm()
                    && configuration.isRsaSigningAvailable()) {
                if (configuration.isPublishNextExternalTokenSigningKeysEnabledV2()) {
                    var oldPublicKey = jwksService.getPublicTokenRsaJwkWithOpaqueId();
                    var newV2PublicKey = jwksService.getNextPublicTokenRsaJwkWithOpaqueIdV2();
                    if (Objects.equals(jwt.getHeader().getKeyID(), newV2PublicKey.getKeyID())) {
                        return jwt.verify(new RSASSAVerifier(newV2PublicKey.toRSAKey()));
                    } else {
                        return jwt.verify(new RSASSAVerifier(oldPublicKey.toRSAKey()));
                    }
                } else {
                    return jwt.verify(
                            new RSASSAVerifier(
                                    jwksService.getPublicTokenRsaJwkWithOpaqueId().toRSAKey()));
                }
            } else {
                if (configuration.isPublishNextExternalTokenSigningKeysEnabledV2()) {
                    var oldPublicKey = jwksService.getPublicTokenJwkWithOpaqueId();
                    var newV2PublicKey = jwksService.getNextPublicTokenJwkWithOpaqueIdV2();
                    if (Objects.equals(jwt.getHeader().getKeyID(), newV2PublicKey.getKeyID())) {
                        return jwt.verify(new ECDSAVerifier(newV2PublicKey.toECKey()));
                    } else {
                        return jwt.verify(new ECDSAVerifier(oldPublicKey.toECKey()));
                    }
                } else {
                    return jwt.verify(
                            new ECDSAVerifier(
                                    jwksService.getPublicTokenJwkWithOpaqueId().toECKey()));
                }
            }

        } catch (JOSEException | java.text.ParseException e) {
            LOG.warn("Unable to validate Signature of Token", e);
            return false;
        }
    }

    public boolean isReauthTokenSignatureValid(String tokenValue) {
        try {
            var jwt = SignedJWT.parse(tokenValue);

            if (configuration.isPublishNextExternalTokenSigningKeysEnabledV2()) {
                var newV2PublicKey = jwksService.getNextPublicTokenJwkWithOpaqueIdV2();
                if (Objects.equals(jwt.getHeader().getKeyID(), newV2PublicKey.getKeyID())) {
                    return jwt.verify(new ECDSAVerifier(newV2PublicKey.toECKey()));
                } else {
                    return validateWithOldECPublicKey(jwt);
                }
            } else {
                return validateWithOldECPublicKey(jwt);
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

    private boolean validateWithOldECPublicKey(SignedJWT jwt) throws JOSEException {
        var oldPublicKey = jwksService.getPublicTokenJwkWithOpaqueId();
        if (configuration.isUseStoredOldIdTokenPublicKeysEnabled()) {
            var oldStoredPublicKeys = jwksService.getStoredOldPublicTokenJwksWithOpaqueId();
            Optional<ECKey> optionalPublicKey =
                    oldStoredPublicKeys.stream()
                            .filter(
                                    key ->
                                            Objects.equals(
                                                    jwt.getHeader().getKeyID(), key.getKeyID()))
                            .findFirst();
            return optionalPublicKey.isPresent()
                    && jwt.verify(new ECDSAVerifier(optionalPublicKey.get()));
        } else {
            return jwt.verify(new ECDSAVerifier(oldPublicKey.toECKey()));
        }
    }
}
