package uk.gov.di.authentication.shared.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.net.MalformedURLException;
import java.util.Date;
import java.util.List;

public class TokenValidationService {

    private final JwksService jwksService;
    private final ConfigurationService configuration;
    private static final Logger LOG = LogManager.getLogger(TokenValidationService.class);

    public TokenValidationService(JwksService jwksService, ConfigurationService configuration) {
        this.jwksService = jwksService;
        this.configuration = configuration;
    }

    public boolean validateAccessTokenSignature(AccessToken accessToken) {
        return isTokenSignatureValid(accessToken.getValue());
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
                return jwt.verify(
                        new RSASSAVerifier(
                                jwksService
                                        .getPublicTokenRsaJwkWithOpaqueId(
                                                jwt.getHeader().getKeyID())
                                        .toRSAKey()));
            } else {
                return jwt.verify(
                        new ECDSAVerifier(
                                jwksService
                                        .getPublicTokenJwkWithOpaqueId(jwt.getHeader().getKeyID())
                                        .toECKey()));
            }

        } catch (JOSEException | java.text.ParseException e) {
            LOG.warn("Unable to validate Signature of Token", e);
            return false;
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
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
