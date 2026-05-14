package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
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
import uk.gov.di.authentication.frontendapi.entity.amc.AMCAuthorizationUrlAndCookie;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCFailureReason;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCScope;
import uk.gov.di.authentication.frontendapi.entity.amc.AccessTokenConfig;
import uk.gov.di.authentication.frontendapi.entity.amc.JourneyOutcomeError;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.JwtFailureReason;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.helpers.HashHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.AccessTokenConstructorService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.JwtService;

import java.io.IOException;
import java.net.URI;
import java.security.interfaces.RSAPublicKey;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static java.util.Collections.singletonList;

public class AMCService {
    private final ConfigurationService configurationService;
    private final NowHelper.NowClock nowClock;
    private final JwtService jwtService;
    private final AccessTokenConstructorService accessTokenConstructorService;
    private static final Logger LOG = LogManager.getLogger(AMCService.class);
    private static final Long CLIENT_ASSERTION_LIFETIME = 5L;

    public AMCService(
            ConfigurationService configurationService,
            NowHelper.NowClock nowClock,
            JwtService jwtService,
            AccessTokenConstructorService accessTokenConstructorService) {
        this.configurationService = configurationService;
        this.nowClock = nowClock;
        this.jwtService = jwtService;
        this.accessTokenConstructorService = accessTokenConstructorService;
    }

    public Result<AMCFailureReason, AMCAuthorizationUrlAndCookie> buildAuthorizationResult(
            String internalPairwiseSubject,
            AMCScope amcScope,
            AuthSessionItem authSessionItem,
            String publicSubjectId,
            String amcRedirectUri,
            List<AccessTokenConfig> accessTokenConfigs,
            RSAPublicKey publicEncryptionKey,
            String encryptionKeyId,
            State state) {
        LOG.info("Building AMC authorization URL");

        return createTransportJWTAndAmcCookie(
                        internalPairwiseSubject,
                        publicSubjectId,
                        amcScope,
                        amcRedirectUri,
                        authSessionItem,
                        accessTokenConfigs,
                        publicEncryptionKey,
                        encryptionKeyId,
                        state)
                .map(
                        encryptedJWTAndAmcCookie -> {
                            AuthorizationRequest authRequest =
                                    new AuthorizationRequest.Builder(
                                                    new ResponseType(ResponseType.Value.CODE),
                                                    new ClientID(
                                                            configurationService.getAMCClientId()))
                                            .endpointURI(configurationService.getAMCAuthorizeURI())
                                            .requestObject(encryptedJWTAndAmcCookie.encryptedJWT)
                                            .scope(new Scope(amcScope.getValue()))
                                            .redirectionURI(URI.create(amcRedirectUri))
                                            .state(state)
                                            .build();
                            String authorizationUrl = authRequest.toURI().toString();
                            LOG.info("AMC authorization URL created");
                            return new AMCAuthorizationUrlAndCookie(
                                    authorizationUrl, encryptedJWTAndAmcCookie.amcCookie);
                        });
    }

    public Result<AMCFailureReason, TokenRequest> buildTokenRequest(
            String authCode, String usedRedirectUrl) {
        var clientAssertionJwt = buildClientAssertionJwt();
        var keyId = configurationService.getAuthToAMCTransportJWTSigningKey();
        var signedJWTResult = jwtService.signJWT(clientAssertionJwt.toJWTClaimsSet(), keyId);
        return signedJWTResult
                .mapFailure(this::mapJwtFailureReason)
                .map(
                        signedJWT ->
                                new TokenRequest(
                                        configurationService.getAMCTokenEndpointURI(),
                                        new PrivateKeyJWT(signedJWT),
                                        new AuthorizationCodeGrant(
                                                new AuthorizationCode(authCode),
                                                URI.create(usedRedirectUrl))));
    }

    public Result<JourneyOutcomeError, HTTPResponse> requestJourneyOutcome(
            UserInfoRequest userInfoRequest, Map<String, String> additionalAmcHeaders) {
        try {
            var request = userInfoRequest.toHTTPRequest();
            additionalAmcHeaders.forEach(request::setHeader);
            var response = request.send();
            if (!response.indicatesSuccess()) {
                return Result.failure(JourneyOutcomeError.ERROR_RESPONSE_FROM_JOURNEY_OUTCOME);
            }
            return Result.success(response);
        } catch (IOException e) {
            return Result.failure(JourneyOutcomeError.IO_EXCEPTION);
        }
    }

    private record EncryptedJWTAndAmcCookie(EncryptedJWT encryptedJWT, String amcCookie) {}

    private Result<AMCFailureReason, EncryptedJWTAndAmcCookie> createTransportJWTAndAmcCookie(
            String internalPairwiseSubject,
            String publicSubjectId,
            AMCScope amcScope,
            String amcRedirectUri,
            AuthSessionItem authSessionItem,
            List<AccessTokenConfig> accessTokenConfigs,
            RSAPublicKey publicEncryptionKey,
            String encryptionKeyId,
            State state) {
        Date issueTime = nowClock.now();
        Date expiryDate = nowClock.nowPlus(CLIENT_ASSERTION_LIFETIME, ChronoUnit.MINUTES);

        return createAccessTokenClaimsMap(
                        accessTokenConfigs,
                        publicSubjectId,
                        authSessionItem.getSessionId(),
                        issueTime,
                        expiryDate)
                .flatMap(
                        accessTokenMap -> {
                            var claimsBuilder =
                                    new JWTClaimsSet.Builder()
                                            .issuer(configurationService.getAMCClientId())
                                            .claim(
                                                    "client_id",
                                                    configurationService.getAMCClientId())
                                            .audience(
                                                    configurationService
                                                            .getAuthToAMCPublicAudience())
                                            .claim("response_type", "code")
                                            .claim("redirect_uri", amcRedirectUri)
                                            .claim("scope", amcScope.getValue())
                                            .claim("state", state.getValue())
                                            .jwtID(UUID.randomUUID().toString())
                                            .issueTime(issueTime)
                                            .notBeforeTime(issueTime)
                                            .expirationTime(expiryDate)
                                            .subject(internalPairwiseSubject)
                                            .claim("email", authSessionItem.getEmailAddress())
                                            .claim("public_sub", publicSubjectId);

                            accessTokenMap.forEach(
                                    (claimName, accessToken) ->
                                            claimsBuilder.claim(claimName, accessToken.getValue()));

                            return jwtService
                                    .signJWT(
                                            claimsBuilder.build(),
                                            configurationService
                                                    .getAuthToAMCTransportJWTSigningKey())
                                    .mapFailure(this::mapJwtFailureReason);
                        })
                .flatMap(
                        signedJWT -> {
                            var hashedCookie = HashHelper.hashSha256String(signedJWT.serialize());
                            return jwtService
                                    .encryptJWT(signedJWT, publicEncryptionKey, encryptionKeyId)
                                    .map(
                                            encryptedJWT ->
                                                    new EncryptedJWTAndAmcCookie(
                                                            encryptedJWT, hashedCookie))
                                    .mapFailure(this::mapJwtFailureReason);
                        });
    }

    private Result<AMCFailureReason, Map<String, BearerAccessToken>> createAccessTokenClaimsMap(
            List<AccessTokenConfig> configs,
            String publicSubjectId,
            String sessionId,
            Date issueTime,
            Date expiryDate) {
        var accessTokens = new HashMap<String, BearerAccessToken>();

        for (AccessTokenConfig config : configs) {
            var result =
                    accessTokenConstructorService
                            .createSignedAccessToken(
                                    publicSubjectId,
                                    config.scope(),
                                    sessionId,
                                    issueTime,
                                    expiryDate,
                                    config.audience(),
                                    configurationService.getAuthIssuerClaim(),
                                    configurationService.getAMCClientId(),
                                    config.signingKey())
                            .mapFailure(this::mapJwtFailureReason);

            if (result.isFailure()) {
                return Result.failure(result.getFailure());
            }

            accessTokens.put(config.accessTokenName(), result.getSuccess());
        }
        return Result.success(accessTokens);
    }

    private JWTAuthenticationClaimsSet buildClientAssertionJwt() {
        LOG.info("Building AMC authorization JWT");

        Date now = nowClock.now();
        Date expiryDate = nowClock.nowPlus(CLIENT_ASSERTION_LIFETIME, ChronoUnit.MINUTES);

        return new JWTAuthenticationClaimsSet(
                new ClientID(configurationService.getAMCClientId()),
                singletonList(new Audience(configurationService.getAuthToAMCPrivateAudience())),
                expiryDate,
                now,
                now,
                new JWTID());
    }

    private AMCFailureReason mapJwtFailureReason(JwtFailureReason jwtFailureReason) {
        return switch (jwtFailureReason) {
            case JWT_ENCODING_ERROR -> AMCFailureReason.JWT_ENCODING_ERROR;
            case UNKNOWN_JWT_SIGNING_ERROR -> AMCFailureReason.UNKNOWN_JWT_SIGNING_ERROR;
            case TRANSCODING_ERROR -> AMCFailureReason.TRANSCODING_ERROR;
            case SIGNING_ERROR, KEY_RETRIEVAL_ERROR -> AMCFailureReason.SIGNING_ERROR;
            case ENCRYPTION_ERROR -> AMCFailureReason.ENCRYPTION_ERROR;
            case UNKNOWN_JWT_ENCRYPTING_ERROR -> AMCFailureReason.UNKNOWN_JWT_ENCRYPTING_ERROR;
            case JWKS_RETRIEVAL_ERROR -> AMCFailureReason.JWKS_RETRIEVAL_ERROR;
        };
    }
}
