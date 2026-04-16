package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import uk.gov.di.authentication.frontendapi.entity.JwtFailureReason;
import uk.gov.di.authentication.frontendapi.entity.amc.AccessTokenScope;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Date;
import java.util.UUID;

public class AccessTokenConstructorService {

    private final JwtService jwtService;
    private final ConfigurationService configurationService;

    public AccessTokenConstructorService(
            JwtService jwtService, ConfigurationService configurationService) {
        this.jwtService = jwtService;
        this.configurationService = configurationService;
    }

    public Result<JwtFailureReason, BearerAccessToken> createSignedAccessToken(
            String internalPairwiseSubject,
            AccessTokenScope scope,
            AuthSessionItem authSessionItem,
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
                        .subject(internalPairwiseSubject)
                        .claim("client_id", clientId)
                        .claim("sid", authSessionItem.getSessionId())
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
