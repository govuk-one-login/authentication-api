package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
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
import uk.gov.di.authentication.frontendapi.entity.JwtFailureReason;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCAuthorizationUrlAndCookie;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCAuthorizeFailureReason;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCScope;
import uk.gov.di.authentication.frontendapi.entity.amc.AccessTokenConfig;
import uk.gov.di.authentication.frontendapi.entity.amc.JourneyOutcomeError;
import uk.gov.di.authentication.frontendapi.exceptions.JwtServiceException;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.helpers.HashHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.io.IOException;
import java.net.URI;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static java.util.Collections.singletonList;

public class AMCService {
    private final ConfigurationService configurationService;
    private final ExternalApiAccessTokenService externalApiAccessTokenService;
    private final NowHelper.NowClock nowClock;
    private final JwtService jwtService;
    private static final Logger LOG = LogManager.getLogger(AMCService.class);
    private static final Long CLIENT_ASSERTION_LIFETIME = 5L;

    public AMCService(
            ConfigurationService configurationService,
            NowHelper.NowClock nowClock,
            JwtService jwtService) {
        this.configurationService = configurationService;
        this.nowClock = nowClock;
        this.jwtService = jwtService;
        this.externalApiAccessTokenService =
                new ExternalApiAccessTokenService(jwtService, configurationService);
    }

    public Result<AMCAuthorizeFailureReason, AMCAuthorizationUrlAndCookie> buildAuthorizationResult(
            String internalPairwiseSubject,
            AMCScope amcScope,
            AuthSessionItem authSessionItem,
            String publicSubject,
            String amcRedirectUri,
            List<AccessTokenConfig> accessTokenConfigs,
            RSAPublicKey publicEncryptionKey,
            State state) {
        LOG.info("Building AMC authorization URL");

        return createTransportJWTAndAmcCookie(
                        internalPairwiseSubject,
                        amcScope,
                        amcRedirectUri,
                        authSessionItem,
                        publicSubject,
                        accessTokenConfigs,
                        publicEncryptionKey,
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
                                            .build();
                            String authorizationUrl = authRequest.toURI().toString();
                            LOG.info("AMC authorization URL created");
                            return new AMCAuthorizationUrlAndCookie(
                                    authorizationUrl, encryptedJWTAndAmcCookie.amcCookie);
                        });
    }

    public Result<AMCAuthorizeFailureReason, TokenRequest> buildTokenRequest(
            String authCode, String usedRedirectUrl) {
        var clientAssertionJwt = buildClientAssertionJwt();
        var keyId = configurationService.getAuthToAMCTransportJWTSigningKey();
        var signedJWTResult = jwtService.signJWT(clientAssertionJwt.toJWTClaimsSet(), keyId);
        return signedJWTResult
                .mapFailure(this::mapSignJwtFailureReason)
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

    private Result<AMCAuthorizeFailureReason, EncryptedJWT> encryptJWT(
            SignedJWT signedJWT, RSAPublicKey publicEncryptionKey) {
        try {
            return Result.success(jwtService.encryptJWT(signedJWT, publicEncryptionKey));
        } catch (JwtServiceException e) {
            Throwable cause = e.getCause();
            if (cause instanceof JOSEException) {
                return Result.failure(AMCAuthorizeFailureReason.ENCRYPTION_ERROR);
            } else if (cause instanceof ParseException) {
                return Result.failure(AMCAuthorizeFailureReason.JWT_ENCODING_ERROR);
            }
            return Result.failure(AMCAuthorizeFailureReason.UNKNOWN_JWT_ENCRYPTING_ERROR);
        }
    }

    private record EncryptedJWTAndAmcCookie(EncryptedJWT encryptedJWT, String amcCookie) {}

    private Result<AMCAuthorizeFailureReason, EncryptedJWTAndAmcCookie>
            createTransportJWTAndAmcCookie(
                    String internalPairwiseSubject,
                    AMCScope amcScope,
                    String amcRedirectUri,
                    AuthSessionItem authSessionItem,
                    String publicSubject,
                    List<AccessTokenConfig> accessTokenConfigs,
                    RSAPublicKey publicEncryptionKey,
                    State state) {
        Date issueTime = nowClock.now();
        Date expiryDate = nowClock.nowPlus(CLIENT_ASSERTION_LIFETIME, ChronoUnit.MINUTES);

        return createAccessTokenClaimsMap(
                        accessTokenConfigs,
                        internalPairwiseSubject,
                        authSessionItem,
                        issueTime,
                        expiryDate)
                .flatMap(
                        accessTokenMap -> {
                            var claimsBuilder =
                                    new JWTClaimsSet.Builder()
                                            .issuer(configurationService.getAuthIssuerClaim())
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
                                            .claim("public_sub", publicSubject);

                            accessTokenMap.forEach(
                                    (claimName, accessToken) ->
                                            claimsBuilder.claim(claimName, accessToken.getValue()));

                            return jwtService
                                    .signJWT(
                                            claimsBuilder.build(),
                                            configurationService
                                                    .getAuthToAMCTransportJWTSigningKey())
                                    .mapFailure(this::mapSignJwtFailureReason);
                        })
                .flatMap(
                        signedJWT -> {
                            var hashedCookie = HashHelper.hashSha256String(signedJWT.serialize());
                            return encryptJWT(signedJWT, publicEncryptionKey)
                                    .map(
                                            encryptedJWT ->
                                                    new EncryptedJWTAndAmcCookie(
                                                            encryptedJWT, hashedCookie));
                        });
    }

    private Result<AMCAuthorizeFailureReason, Map<String, BearerAccessToken>>
            createAccessTokenClaimsMap(
                    List<AccessTokenConfig> configs,
                    String internalPairwiseSubject,
                    AuthSessionItem authSessionItem,
                    Date issueTime,
                    Date expiryDate) {
        var accessTokens = new HashMap<String, BearerAccessToken>();

        for (AccessTokenConfig config : configs) {
            var result =
                    externalApiAccessTokenService.createSignedAccessToken(
                            internalPairwiseSubject,
                            config.scope(),
                            authSessionItem,
                            issueTime,
                            expiryDate,
                            config.audience(),
                            configurationService.getAuthIssuerClaim(),
                            configurationService.getAMCClientId(),
                            config.signingKey());

            if (result.isFailure()) {
                return Result.failure(mapSignJwtFailureReason(result.getFailure()));
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

    private AMCAuthorizeFailureReason mapSignJwtFailureReason(JwtFailureReason jwtFailureReason) {
        return switch (jwtFailureReason) {
            case JWT_ENCODING_ERROR -> AMCAuthorizeFailureReason.JWT_ENCODING_ERROR;
            case UNKNOWN_JWT_SIGNING_ERROR -> AMCAuthorizeFailureReason.UNKNOWN_JWT_SIGNING_ERROR;
            case TRANSCODING_ERROR -> AMCAuthorizeFailureReason.TRANSCODING_ERROR;
            case SIGNING_ERROR, KEY_RETRIEVAL_ERROR -> AMCAuthorizeFailureReason.SIGNING_ERROR;
            case ENCRYPTION_ERROR -> AMCAuthorizeFailureReason.ENCRYPTION_ERROR;
            case UNKNOWN_JWT_ENCRYPTING_ERROR -> AMCAuthorizeFailureReason
                    .UNKNOWN_JWT_ENCRYPTING_ERROR;
            case JWKS_RETRIEVAL_ERROR -> AMCAuthorizeFailureReason.JWKS_RETRIEVAL_ERROR;
        };
    }
}
