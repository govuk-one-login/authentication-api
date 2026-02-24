package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.exception.SdkException;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCScope;
import uk.gov.di.authentication.frontendapi.entity.amc.JourneyOutcomeError;
import uk.gov.di.authentication.frontendapi.entity.amc.JwtFailureReason;
import uk.gov.di.authentication.frontendapi.exceptions.JwtServiceException;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.io.IOException;
import java.net.URI;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static java.util.Collections.singletonList;

public class AMCService {
    private final ConfigurationService configurationService;
    private final NowHelper.NowClock nowClock;
    private final JwtService jwtService;
    private static final Logger LOG = LogManager.getLogger(AMCService.class);

    public AMCService(
            ConfigurationService configurationService,
            NowHelper.NowClock nowClock,
            JwtService jwtService) {
        this.configurationService = configurationService;
        this.nowClock = nowClock;
        this.jwtService = jwtService;
    }

    private Result<JwtFailureReason, SignedJWT> signJWT(JWTClaimsSet jwtClaims, String keyId) {
        try {
            return Result.success(jwtService.signJWT(jwtClaims, keyId));
        } catch (JwtServiceException e) {
            Throwable cause = e.getCause();
            if (cause instanceof SdkException) {
                return Result.failure(JwtFailureReason.SIGNING_ERROR);
            } else if (cause instanceof ParseException) {
                return Result.failure(JwtFailureReason.JWT_ENCODING_ERROR);
            } else if (cause instanceof JOSEException) {
                return Result.failure(JwtFailureReason.TRANSCODING_ERROR);
            }
            return Result.failure(JwtFailureReason.UNKNOWN_JWT_SIGNING_ERROR);
        }
    }

    private Result<JwtFailureReason, EncryptedJWT> encryptJWT(
            SignedJWT signedJWT, RSAPublicKey publicEncryptionKey) {
        try {
            return Result.success(jwtService.encryptJWT(signedJWT, publicEncryptionKey));
        } catch (JwtServiceException e) {
            Throwable cause = e.getCause();
            if (cause instanceof JOSEException) {
                return Result.failure(JwtFailureReason.ENCRYPTION_ERROR);
            } else if (cause instanceof ParseException) {
                return Result.failure(JwtFailureReason.JWT_ENCODING_ERROR);
            }
            return Result.failure(JwtFailureReason.UNKNOWN_JWT_ENCRYPTING_ERROR);
        }
    }

    private Result<JwtFailureReason, BearerAccessToken> createAccessToken(
            String internalPairwiseSubject, AMCScope[] scope, AuthSessionItem authSessionItem) {
        Date issueTime = nowClock.now();
        Date expiryDate =
                nowClock.nowPlus(configurationService.getSessionExpiry(), ChronoUnit.SECONDS);
        List<String> scopeValues = Arrays.stream(scope).map(AMCScope::getValue).toList();

        var claims =
                new JWTClaimsSet.Builder()
                        .claim("scope", scopeValues)
                        .issuer(configurationService.getAuthIssuerClaim())
                        .audience(configurationService.getAuthToAMAPIAudience())
                        .expirationTime(expiryDate)
                        .issueTime(issueTime)
                        .notBeforeTime(issueTime)
                        .subject(internalPairwiseSubject)
                        .claim("client_id", configurationService.getAMCClientId())
                        .claim("sid", authSessionItem.getSessionId())
                        .jwtID(UUID.randomUUID().toString())
                        .build();

        return signJWT(
                        claims,
                        configurationService.getAuthToAccountManagementPrivateSigningKeyAlias())
                .map(
                        signedJWT -> {
                            Scope oauthScope = new Scope(scopeValues.toArray(new String[0]));
                            return new BearerAccessToken(
                                    signedJWT.serialize(),
                                    configurationService.getSessionExpiry(),
                                    oauthScope);
                        });
    }

    private Result<JwtFailureReason, EncryptedJWT> createCompositeJWT(
            String internalPairwiseSubject,
            AMCScope[] scope,
            AuthSessionItem authSessionItem,
            String clientSessionId,
            String publicSubject) {
        List<String> scopeValues = Arrays.stream(scope).map(AMCScope::getValue).toList();
        Date issueTime = nowClock.now();
        Date expiryDate =
                nowClock.nowPlus(configurationService.getSessionExpiry(), ChronoUnit.SECONDS);

        return createAccessToken(internalPairwiseSubject, scope, authSessionItem)
                .flatMap(
                        accessToken -> {
                            var claims =
                                    new JWTClaimsSet.Builder()
                                            .issuer(configurationService.getAuthIssuerClaim())
                                            .claim(
                                                    "client_id",
                                                    configurationService.getAMCClientId())
                                            .audience(configurationService.getAuthToAMCAudience())
                                            .claim("response_type", "code")
                                            .claim(
                                                    "redirect_uri",
                                                    configurationService.getAMCRedirectURI())
                                            .claim("scope", scopeValues)
                                            .claim("state", new State().getValue())
                                            .jwtID(UUID.randomUUID().toString())
                                            .issueTime(issueTime)
                                            .notBeforeTime(issueTime)
                                            .expirationTime(expiryDate)
                                            .subject(internalPairwiseSubject)
                                            .claim("email", authSessionItem.getEmailAddress())
                                            .claim("govuk_signin_journey_id", clientSessionId)
                                            .claim("public_sub", publicSubject)
                                            .claim("access_token", accessToken.getValue())
                                            .build();

                            return signJWT(
                                            claims,
                                            configurationService
                                                    .getAuthToAMCPrivateSigningKeyAlias())
                                    .flatMap(
                                            signedJWT -> {
                                                try {
                                                    RSAPublicKey publicKey =
                                                            JWK.parseFromPEMEncodedObjects(
                                                                            configurationService
                                                                                    .getAuthToAMCPublicEncryptionKey())
                                                                    .toRSAKey()
                                                                    .toRSAPublicKey();
                                                    return encryptJWT(signedJWT, publicKey);
                                                } catch (JOSEException e) {
                                                    return Result.failure(
                                                            JwtFailureReason.JWT_ENCODING_ERROR);
                                                }
                                            });
                        });
    }

    public Result<JwtFailureReason, String> buildAuthorizationUrl(
            String internalPairwiseSubject,
            AMCScope[] scope,
            AuthSessionItem authSessionItem,
            String clientSessionId,
            String publicSubject) {
        LOG.info("Building AMC authorization URL");
        return createCompositeJWT(
                        internalPairwiseSubject,
                        scope,
                        authSessionItem,
                        clientSessionId,
                        publicSubject)
                .map(
                        requestJWT -> {
                            AuthorizationRequest authRequest =
                                    new AuthorizationRequest.Builder(
                                                    new ResponseType(ResponseType.Value.CODE),
                                                    new ClientID(
                                                            configurationService.getAMCClientId()))
                                            .endpointURI(configurationService.getAMCAuthorizeURI())
                                            .requestObject(requestJWT)
                                            .build();
                            String authorizationUrl = authRequest.toURI().toString();
                            LOG.info("AMC authorization URL created");
                            return authorizationUrl;
                        });
    }

    public Result<JwtFailureReason, TokenRequest> buildTokenRequest(String authCode) {
        var clientAssertionJwt = buildClientAssertionJwt();
        var keyId = configurationService.getAuthToAMCPrivateSigningKeyAlias();
        var signedJWTResult = signJWT(clientAssertionJwt.toJWTClaimsSet(), keyId);
        return signedJWTResult.map(
                signedJWT ->
                        new TokenRequest(
                                configurationService.getAMCTokenEndpointURI(),
                                new PrivateKeyJWT(signedJWT),
                                new AuthorizationCodeGrant(
                                        new AuthorizationCode(authCode),
                                        URI.create(configurationService.getAMCRedirectURI()))));
    }

    public Result<JourneyOutcomeError, HTTPResponse> requestJourneyOutcome(
            UserInfoRequest userInfoRequest) {
        try {
            var response = userInfoRequest.toHTTPRequest().send();
            if (!response.indicatesSuccess()) {
                return Result.failure(JourneyOutcomeError.ERROR_RESPONSE_FROM_JOURNEY_OUTCOME);
            }
            return Result.success(response);
        } catch (IOException e) {
            return Result.failure(JourneyOutcomeError.IO_EXCEPTION);
        }
    }

    private JWTAuthenticationClaimsSet buildClientAssertionJwt() {
        LOG.info("Building AMC authorization JWT");

        Date now = nowClock.now();
        Date expiryDate =
                nowClock.nowPlus(configurationService.getSessionExpiry(), ChronoUnit.SECONDS);

        return new JWTAuthenticationClaimsSet(
                new ClientID(configurationService.getAMCClientId()),
                singletonList(new Audience(configurationService.getAuthToAMCPrivateAudience())),
                expiryDate,
                now,
                now,
                new JWTID());
    }
}
