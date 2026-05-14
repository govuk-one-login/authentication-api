package uk.gov.di.authentication.shared.services;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import uk.gov.di.authentication.shared.entity.AccessTokenScope;
import uk.gov.di.authentication.shared.entity.JwtFailureReason;
import uk.gov.di.authentication.shared.entity.Result;

import java.util.Date;
import java.util.UUID;

public class AccessTokenConstructorService {

    private final JwtService jwtService;
    private final ConfigurationService configurationService;

    public AccessTokenConstructorService(ConfigurationService configurationService) {
        this.jwtService = new JwtService(new KmsConnectionService(configurationService));
        this.configurationService = configurationService;
    }

    public AccessTokenConstructorService(
            ConfigurationService configurationService, JwtService jwtService) {
        this.configurationService = configurationService;
        this.jwtService = jwtService;
    }

    public Result<JwtFailureReason, BearerAccessToken> createSignedAccessToken(
            String publicSubjectId,
            AccessTokenScope scope,
            String sessionId,
            Date issueTime,
            Date expiryDate,
            String audience,
            String issuer,
            String clientId,
            String signingKey) {
        var claims =
                new JWTClaimsSet.Builder()
                        .claim("scope", scope.getValue())
                        .issuer(issuer)
                        .audience(audience)
                        .expirationTime(expiryDate)
                        .issueTime(issueTime)
                        .notBeforeTime(issueTime)
                        .subject(publicSubjectId)
                        .claim("client_id", clientId)
                        .claim("sid", sessionId)
                        .jwtID(UUID.randomUUID().toString())
                        .build();

        return jwtService
                .signJWT(claims, signingKey)
                .map(signedJWT -> signedJwtToAccessToken(signedJWT, scope));
    }

    private BearerAccessToken signedJwtToAccessToken(SignedJWT signedJWT, AccessTokenScope scope) {
        return new BearerAccessToken(
                signedJWT.serialize(),
                configurationService.getSessionExpiry(),
                new Scope(scope.getValue()));
    }
}
