package uk.gov.di.orchestration.shared.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.SessionID;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.entity.AccessTokenStore;
import uk.gov.di.orchestration.shared.entity.RefreshTokenStore;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.helpers.RequestBodyHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.serialization.Json.JsonException;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import static uk.gov.di.orchestration.shared.helpers.HashHelper.hashSha256String;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class TokenService {

    private final ConfigurationService configService;
    private final RedisConnectionService redisConnectionService;
    private final KmsConnectionService kmsConnectionService;
    private final OidcAPI oidcApi;
    private static final JWSAlgorithm TOKEN_ALGORITHM = JWSAlgorithm.ES256;
    private static final Logger LOG = LogManager.getLogger(TokenService.class);
    private static final String REFRESH_TOKEN_PREFIX = "REFRESH_TOKEN:";
    private static final String ACCESS_TOKEN_PREFIX = "ACCESS_TOKEN:";
    private static final List<String> ALLOWED_GRANTS =
            List.of(GrantType.AUTHORIZATION_CODE.getValue(), GrantType.REFRESH_TOKEN.getValue());

    private final Json objectMapper = SerializationService.getInstance();

    public TokenService(
            ConfigurationService configService,
            RedisConnectionService redisConnectionService,
            KmsConnectionService kmsConnectionService,
            OidcAPI oidcApi) {
        this.configService = configService;
        this.redisConnectionService = redisConnectionService;
        this.kmsConnectionService = kmsConnectionService;
        this.oidcApi = oidcApi;
    }

    public OIDCTokenResponse generateTokenResponse(
            String clientID,
            Subject internalSubject,
            Scope authRequestScopes,
            Map<String, Object> additionalTokenClaims,
            Subject rpPairwiseSubject,
            Subject internalPairwiseSubject,
            OIDCClaimsRequest claimsRequest,
            boolean isDocAppJourney,
            JWSAlgorithm signingAlgorithm,
            String journeyId,
            String vot,
            Long authTime) {
        List<String> scopesForToken = authRequestScopes.toStringList();
        AccessToken accessToken =
                segmentedFunctionCall(
                        "generateAndStoreAccessToken",
                        () ->
                                generateAndStoreAccessToken(
                                        clientID,
                                        scopesForToken,
                                        rpPairwiseSubject,
                                        internalPairwiseSubject,
                                        claimsRequest,
                                        signingAlgorithm,
                                        journeyId));
        AccessTokenHash accessTokenHash =
                segmentedFunctionCall(
                        "AccessTokenHash.compute",
                        () -> AccessTokenHash.compute(accessToken, TOKEN_ALGORITHM, null));

        SignedJWT idToken =
                segmentedFunctionCall(
                        "generateIDToken",
                        () ->
                                generateIDToken(
                                        clientID,
                                        rpPairwiseSubject,
                                        additionalTokenClaims,
                                        accessTokenHash,
                                        vot,
                                        isDocAppJourney,
                                        signingAlgorithm,
                                        journeyId,
                                        authTime));
        if (scopesForToken.contains(OIDCScopeValue.OFFLINE_ACCESS.getValue())) {
            RefreshToken refreshToken =
                    segmentedFunctionCall(
                            "generateAndStoreRefreshToken",
                            () ->
                                    generateAndStoreRefreshToken(
                                            clientID,
                                            internalSubject,
                                            scopesForToken,
                                            rpPairwiseSubject,
                                            internalPairwiseSubject,
                                            signingAlgorithm));
            return new OIDCTokenResponse(new OIDCTokens(idToken, accessToken, refreshToken));
        } else {
            return new OIDCTokenResponse(new OIDCTokens(idToken, accessToken, null));
        }
    }

    public OIDCTokenResponse generateRefreshTokenResponse(
            String clientID,
            Subject internalSubject,
            List<String> scopes,
            Subject rpPaiwiseSubject,
            Subject internalPairwiseSubject,
            JWSAlgorithm signingAlgorithm) {
        AccessToken accessToken =
                generateAndStoreAccessToken(
                        clientID,
                        scopes,
                        rpPaiwiseSubject,
                        internalPairwiseSubject,
                        null,
                        signingAlgorithm,
                        "refreshToken");
        RefreshToken refreshToken =
                generateAndStoreRefreshToken(
                        clientID,
                        internalSubject,
                        scopes,
                        rpPaiwiseSubject,
                        internalPairwiseSubject,
                        signingAlgorithm);
        return new OIDCTokenResponse(new OIDCTokens(accessToken, refreshToken));
    }

    public Optional<ErrorObject> validateTokenRequestParams(String tokenRequestBody) {
        Map<String, String> requestBody = RequestBodyHelper.parseRequestBody(tokenRequestBody);
        if (!requestBody.containsKey("grant_type")) {
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "Request is missing grant_type parameter"));
        }
        if (!ALLOWED_GRANTS.contains(requestBody.get("grant_type"))) {
            return Optional.of(OAuth2Error.UNSUPPORTED_GRANT_TYPE);
        }
        if (requestBody.get("grant_type").equals(GrantType.AUTHORIZATION_CODE.getValue())) {
            if (!requestBody.containsKey("redirect_uri")) {
                return Optional.of(
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Request is missing redirect_uri parameter"));
            }
            if (!requestBody.containsKey("code") || requestBody.get("code").isEmpty()) {
                return Optional.of(
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Request is missing code parameter"));
            }
        } else if (requestBody.get("grant_type").equals(GrantType.REFRESH_TOKEN.getValue())) {
            return validateRefreshRequestParams(requestBody);
        }
        return Optional.empty();
    }

    private Optional<ErrorObject> validateRefreshRequestParams(Map<String, String> requestBody) {
        if (!requestBody.containsKey("refresh_token")) {
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE, "Request is missing refresh token"));
        }
        try {
            new RefreshToken(requestBody.get("refresh_token"));
        } catch (IllegalArgumentException e) {
            LOG.warn("Invalid RefreshToken", e);
            return Optional.of(
                    new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, "Invalid refresh token"));
        }
        return Optional.empty();
    }

    private SignedJWT generateIDToken(
            String clientId,
            Subject subject,
            Map<String, Object> additionalTokenClaims,
            AccessTokenHash accessTokenHash,
            String vot,
            boolean isDocAppJourney,
            JWSAlgorithm signingAlgorithm,
            String journeyId,
            Long authTime) {

        LOG.info("Generating IdToken");
        URI trustMarkUri = oidcApi.trustmarkURI();
        Date expiryDate = NowHelper.nowPlus(configService.getIDTokenExpiry(), ChronoUnit.SECONDS);
        IDTokenClaimsSet idTokenClaims =
                new IDTokenClaimsSet(
                        new Issuer(oidcApi.baseURI().toString()),
                        subject,
                        List.of(new Audience(clientId)),
                        expiryDate,
                        NowHelper.now());

        idTokenClaims.setAccessTokenHash(accessTokenHash);
        idTokenClaims.setSessionID(new SessionID(journeyId));

        idTokenClaims.putAll(additionalTokenClaims);
        if (!isDocAppJourney) {
            idTokenClaims.setClaim("vot", vot);
            idTokenClaims.setClaim("auth_time", authTime);
        }
        idTokenClaims.setClaim("vtm", trustMarkUri.toString());

        try {
            return generateSignedJwtUsingExternalKey(
                    idTokenClaims.toJWTClaimsSet(), Optional.empty(), signingAlgorithm);
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            LOG.error("Error when trying to parse IDTokenClaims to JWTClaimSet", e);
            throw new RuntimeException(e);
        }
    }

    public AccessToken generateStorageToken(Subject internalPairwiseSubject) {

        LOG.info("Generating storage token");
        Date expiryDate = NowHelper.nowPlus(configService.getSessionExpiry(), ChronoUnit.SECONDS);
        var jwtID = UUID.randomUUID().toString();

        LOG.info("Storage token being created with JWTID: {}", jwtID);

        List<String> aud =
                List.of(
                        configService.getCredentialStoreURI().toString(),
                        configService.getIPVAudience());

        JWTClaimsSet.Builder claimSetBuilder =
                new JWTClaimsSet.Builder()
                        .issuer(oidcApi.baseURI().toString())
                        .audience(aud)
                        .expirationTime(expiryDate)
                        .issueTime(NowHelper.now())
                        .subject(internalPairwiseSubject.getValue())
                        .jwtID(jwtID)
                        .claim("scope", "proving");

        SignedJWT signedJWT =
                generateSignedJwtUsingStorageKey(claimSetBuilder.build(), Optional.empty());

        return new BearerAccessToken(
                signedJWT.serialize(), configService.getAccessTokenExpiry(), null);
    }

    private AccessToken generateAndStoreAccessToken(
            String clientId,
            List<String> scopes,
            Subject rpPairwiseSubject,
            Subject internalPairwiseSubject,
            OIDCClaimsRequest claimsRequest,
            JWSAlgorithm signingAlgorithm,
            String journeyId) {

        LOG.info("Generating AccessToken");
        Date expiryDate =
                NowHelper.nowPlus(configService.getAccessTokenExpiry(), ChronoUnit.SECONDS);
        var jwtID = UUID.randomUUID().toString();

        LOG.info("AccessToken being created with JWTID: {}", jwtID);

        JWTClaimsSet.Builder claimSetBuilder =
                new JWTClaimsSet.Builder()
                        .claim("scope", scopes)
                        .issuer(oidcApi.baseURI().toString())
                        .expirationTime(expiryDate)
                        .issueTime(NowHelper.now())
                        .claim("client_id", clientId)
                        .claim("sid", journeyId)
                        .subject(rpPairwiseSubject.getValue())
                        .jwtID(jwtID);

        if (Objects.nonNull(claimsRequest)
                && Objects.nonNull(claimsRequest.getUserInfoClaimsRequest())) {
            LOG.info("Populating identity claims in access token");
            claimSetBuilder.claim(
                    "claims",
                    claimsRequest.getUserInfoClaimsRequest().getEntries().stream()
                            .map(ClaimsSetRequest.Entry::getClaimName)
                            .toList());
        } else {
            LOG.info("No identity claims to populate in access token");
        }

        SignedJWT signedJWT =
                generateSignedJwtUsingExternalKey(
                        claimSetBuilder.build(), Optional.empty(), signingAlgorithm);
        AccessToken accessToken =
                new BearerAccessToken(
                        signedJWT.serialize(), configService.getAccessTokenExpiry(), null);

        try {
            redisConnectionService.saveWithExpiry(
                    ACCESS_TOKEN_PREFIX + clientId + "." + rpPairwiseSubject.getValue(),
                    objectMapper.writeValueAsString(
                            new AccessTokenStore(
                                    accessToken.getValue(),
                                    internalPairwiseSubject.getValue(),
                                    journeyId)),
                    configService.getAccessTokenExpiry());
        } catch (JsonException e) {
            LOG.error("Unable to save access token to Redis");
            throw new RuntimeException(e);
        }
        return accessToken;
    }

    private RefreshToken generateAndStoreRefreshToken(
            String clientId,
            Subject internalSubject,
            List<String> scopes,
            Subject rpPairwiseSubject,
            Subject internalPairwiseSubject,
            JWSAlgorithm signingAlgorithm) {
        LOG.info("Generating RefreshToken");
        Date expiryDate = NowHelper.nowPlus(configService.getSessionExpiry(), ChronoUnit.SECONDS);
        var jwtId = IdGenerator.generate();
        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .claim("scope", scopes)
                        .issuer(oidcApi.baseURI().toString())
                        .expirationTime(expiryDate)
                        .issueTime(NowHelper.now())
                        .claim("client_id", clientId)
                        .subject(rpPairwiseSubject.getValue())
                        .jwtID(jwtId)
                        .build();

        SignedJWT signedJWT =
                generateSignedJwtUsingExternalKey(claimsSet, Optional.empty(), signingAlgorithm);
        RefreshToken refreshToken = new RefreshToken(signedJWT.serialize());

        String redisKey = REFRESH_TOKEN_PREFIX + jwtId;
        var store =
                new RefreshTokenStore(
                        refreshToken.getValue(),
                        internalSubject.toString(),
                        internalPairwiseSubject.toString());
        try {
            redisConnectionService.saveWithExpiry(
                    redisKey,
                    objectMapper.writeValueAsString(store),
                    configService.getSessionExpiry());
        } catch (JsonException e) {
            throw new RuntimeException("Error serializing refresh token store", e);
        }

        return refreshToken;
    }

    public SignedJWT generateSignedJwtUsingExternalKey(
            JWTClaimsSet claimsSet, Optional<String> type, JWSAlgorithm algorithm) {
        String alias =
                algorithm == JWSAlgorithm.ES256
                        ? configService.getExternalTokenSigningKeyAlias()
                        : configService.getExternalTokenSigningKeyRsaAlias();
        return generateSignedJWT(claimsSet, type, algorithm, alias);
    }

    public SignedJWT generateSignedJwtUsingStorageKey(
            JWTClaimsSet claimsSet, Optional<String> type) {
        return generateSignedJWT(
                claimsSet,
                type,
                JWSAlgorithm.ES256,
                configService.getStorageTokenSigningKeyAlias());
    }

    private SignedJWT generateSignedJWT(
            JWTClaimsSet claimsSet,
            Optional<String> type,
            JWSAlgorithm algorithm,
            String signingKeyAlias) {

        var signingKeyId =
                kmsConnectionService
                        .getPublicKey(GetPublicKeyRequest.builder().keyId(signingKeyAlias).build())
                        .keyId();

        try {
            var jwsHeader = new JWSHeader.Builder(algorithm).keyID(hashSha256String(signingKeyId));

            type.map(JOSEObjectType::new).ifPresent(jwsHeader::type);

            var signingAlgorithm =
                    algorithm == JWSAlgorithm.ES256
                            ? SigningAlgorithmSpec.ECDSA_SHA_256
                            : SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256;

            Base64URL encodedHeader = jwsHeader.build().toBase64URL();
            Base64URL encodedClaims = Base64URL.encode(claimsSet.toString());
            String message = encodedHeader + "." + encodedClaims;
            SignRequest signRequest =
                    SignRequest.builder()
                            .message(
                                    SdkBytes.fromByteArray(
                                            message.getBytes(StandardCharsets.UTF_8)))
                            .keyId(signingKeyId)
                            .signingAlgorithm(signingAlgorithm)
                            .build();
            SignResponse signResult = kmsConnectionService.sign(signRequest);
            LOG.info("Token has been signed successfully using {}", algorithm.getName());

            if (algorithm == JWSAlgorithm.RS256) {
                return SignedJWT.parse(
                        message + "." + Base64URL.encode(signResult.signature().asByteArray()));
            }

            String signature =
                    Base64URL.encode(
                                    ECDSA.transcodeSignatureToConcat(
                                            signResult.signature().asByteArray(),
                                            ECDSA.getSignatureByteArrayLength(algorithm)))
                            .toString();
            return SignedJWT.parse(message + "." + signature);
        } catch (java.text.ParseException | JOSEException e) {
            LOG.error("Exception thrown when trying to parse SignedJWT or JWTClaimSet", e);
            throw new RuntimeException(e);
        }
    }
}
