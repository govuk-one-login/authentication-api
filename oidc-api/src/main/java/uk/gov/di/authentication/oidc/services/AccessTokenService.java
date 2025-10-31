package uk.gov.di.authentication.oidc.services;

import com.google.gson.Gson;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.oauth2.sdk.util.JSONArrayUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.entity.AccessTokenInfo;
import uk.gov.di.orchestration.shared.entity.AccessTokenStore;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.OrchAccessTokenItem;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.entity.ValidScopes;
import uk.gov.di.orchestration.shared.exceptions.AccessTokenException;
import uk.gov.di.orchestration.shared.exceptions.OrchAccessTokenException;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.serialization.Json.JsonException;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.OrchAccessTokenService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.TokenValidationService;

import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class AccessTokenService {

    private static final Logger LOG = LogManager.getLogger(AccessTokenService.class);
    private final RedisConnectionService redisConnectionService;
    private final DynamoClientService clientService;
    private final TokenValidationService tokenValidationService;
    private final OrchAccessTokenService orchAccessTokenService;
    private final Json objectMapper = SerializationService.getInstance();
    private static final String ACCESS_TOKEN_PREFIX = "ACCESS_TOKEN:";
    private static final String INVALID_ACCESS_TOKEN = "Invalid Access Token";

    public AccessTokenService(
            RedisConnectionService redisConnectionService,
            DynamoClientService clientService,
            TokenValidationService tokenValidationService,
            OrchAccessTokenService orchAccessTokenService) {
        this.redisConnectionService = redisConnectionService;
        this.clientService = clientService;
        this.tokenValidationService = tokenValidationService;
        this.orchAccessTokenService = orchAccessTokenService;
    }

    public AccessTokenInfo parse(String authorizationHeader, boolean identityEnabled)
            throws AccessTokenException {
        AccessToken accessToken;
        try {
            accessToken = AccessToken.parse(authorizationHeader, AccessTokenType.BEARER);
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            throw new AccessTokenException(
                    "Unable to parse AccessToken", BearerTokenError.INVALID_TOKEN);
        }

        SignedJWT signedJWT;
        JWTClaimsSet claimsSet;
        ClientRegistry client;
        List<String> scopes;
        List<String> identityClaims = null;
        try {
            signedJWT = SignedJWT.parse(accessToken.getValue());
            claimsSet = signedJWT.getJWTClaimsSet();
            LOG.info(
                    "Successfully processed UserInfo request with JWT ID of {}",
                    claimsSet.getJWTID());

            if (hasAccessTokenExpired(claimsSet.getExpirationTime())) {
                throw new AccessTokenException(
                        INVALID_ACCESS_TOKEN, BearerTokenError.INVALID_TOKEN);
            }
            if (!tokenValidationService.isTokenSignatureValid(accessToken.getValue())) {
                throw new AccessTokenException(
                        "Unable to validate AccessToken signature", BearerTokenError.INVALID_TOKEN);
            }

            var clientID =
                    Optional.ofNullable(claimsSet.getStringClaim("client_id"))
                            .orElseThrow(
                                    () ->
                                            new AccessTokenException(
                                                    "ClientID is null",
                                                    BearerTokenError.INVALID_TOKEN));
            attachLogFieldToLogs(CLIENT_ID, clientID);

            client =
                    clientService
                            .getClient(clientID)
                            .orElseThrow(
                                    () ->
                                            new AccessTokenException(
                                                    "Client not found",
                                                    BearerTokenError.INVALID_TOKEN));

            scopes = getScopesFromClaimsSet(claimsSet);
            List<String> clientScopes = client.getScopes();
            if (!ValidScopes.areScopesValid(scopes) || !clientScopes.containsAll(scopes)) {
                throw new AccessTokenException("Invalid Scopes", OAuth2Error.INVALID_SCOPE);
            }

            if (identityEnabled && client.isIdentityVerificationSupported()) {
                LOG.info("Identity is enabled AND client supports identity verification");
                identityClaims = getIdentityClaims(claimsSet);
            }
        } catch (ParseException e) {
            throw new AccessTokenException(
                    "Unable to parse AccessToken to SignedJWT", BearerTokenError.INVALID_TOKEN);
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            throw new AccessTokenException(
                    "Unable to parse ClaimSet in AccessToken", BearerTokenError.INVALID_TOKEN);
        }

        var subject = claimsSet.getSubject();
        var accessTokenStore = getAccessTokenStore(client.getClientID(), subject);
        if (accessTokenStore.isEmpty()) {
            LOG.warn(
                    "Access Token Store is empty. Access Token expires at: {}. CurrentDateTime is: {}. JWTID in Access Token sent in request: {}",
                    claimsSet.getExpirationTime(),
                    NowHelper.now(),
                    claimsSet.getJWTID());
            throw new AccessTokenException(INVALID_ACCESS_TOKEN, BearerTokenError.INVALID_TOKEN);
        }
        if (!accessTokenStore.get().getToken().equals(accessToken.getValue())) {
            String storeJwtId;
            try {
                storeJwtId =
                        SignedJWT.parse(accessTokenStore.get().getToken())
                                .getJWTClaimsSet()
                                .getJWTID();
            } catch (ParseException e) {
                throw new AccessTokenException(
                        "Unable to parse Access Token from store", BearerTokenError.INVALID_TOKEN);
            }
            LOG.warn(
                    "Access Token in Access Token Store (JWTID: {}), is different to Access Token sent in request (JWTID: {})",
                    storeJwtId,
                    claimsSet.getJWTID());
            throw new AccessTokenException(INVALID_ACCESS_TOKEN, BearerTokenError.INVALID_TOKEN);
        }

        String clientAndRpPairwiseId = client.getClientID() + "." + subject;
        Optional<OrchAccessTokenItem> orchAccessTokenItem;
        try {
            orchAccessTokenItem =
                    orchAccessTokenService
                            .getAccessTokensForClientAndRpPairwiseId(clientAndRpPairwiseId)
                            .stream()
                            .filter(item -> Objects.equals(item.getToken(), accessToken.getValue()))
                            .findFirst();

            if (orchAccessTokenItem.isEmpty()) {
                LOG.warn("There is no access token in dynamo matching the token in the request");
            } else {
                LOG.info(
                        "Token value from access token in dynamo matches the token value in redis");
                LOG.info(
                        "Does internal pairwise subject id from access token in dynamo match redis? {}",
                        Objects.equals(
                                orchAccessTokenItem.get().getInternalPairwiseSubjectId(),
                                accessTokenStore.get().getInternalPairwiseSubjectId()));
                LOG.info(
                        "Does client session id from access token in dynamo match redis? {}",
                        Objects.equals(
                                orchAccessTokenItem.get().getClientSessionId(),
                                accessTokenStore.get().getJourneyId()));
                if (orchAccessTokenItem.get().getAuthCode().equals("placeholder-for-auth-code")) {
                    LOG.info("The access token in dynamo has a placeholder for auth code.");
                }
            }
        } catch (OrchAccessTokenException e) {
            LOG.warn("Unable to get Orch Access Token from Dynamo");
        }

        return new AccessTokenInfo(
                accessTokenStore.get(), subject, scopes, identityClaims, client.getClientID());
    }

    private boolean hasAccessTokenExpired(Date expirationTime) {
        var currentDateTime = NowHelper.now();
        if (DateUtils.isBefore(expirationTime, currentDateTime, 0)) {
            LOG.warn(
                    "Access Token has expired. Access Token expires at: {}. CurrentDateTime is: {}",
                    expirationTime,
                    currentDateTime);
            return true;
        }
        return false;
    }

    private Optional<AccessTokenStore> getAccessTokenStore(String clientId, String subjectId) {
        String result =
                redisConnectionService.getValue(ACCESS_TOKEN_PREFIX + clientId + "." + subjectId);
        try {
            return Optional.ofNullable(objectMapper.readValue(result, AccessTokenStore.class));
        } catch (JsonException | IllegalArgumentException e) {
            LOG.error("Error getting AccessToken from Redis", e);
            return Optional.empty();
        }
    }

    private List<String> getIdentityClaims(JWTClaimsSet claimsSet)
            throws com.nimbusds.oauth2.sdk.ParseException, AccessTokenException {
        if (Objects.isNull(claimsSet.getClaim("claims"))) {
            LOG.info("No identity claims in AccessToken");
            return null;
        }
        var identityClaims =
                JSONArrayUtils.parse(new Gson().toJson(claimsSet.getClaim("claims"))).stream()
                        .map(Objects::toString)
                        .toList();
        if (!ValidClaims.getAllValidClaims().containsAll(identityClaims)) {
            LOG.warn("Invalid set of Identity claims present in access token: {}", identityClaims);
            throw new AccessTokenException("Invalid Identity claims", OAuth2Error.INVALID_REQUEST);
        }
        LOG.info("Identity claims present in Access token");
        return identityClaims;
    }

    private List<String> getScopesFromClaimsSet(JWTClaimsSet claimsSet)
            throws com.nimbusds.oauth2.sdk.ParseException {
        return JSONArrayUtils.parse(new Gson().toJson(claimsSet.getClaim("scope"))).stream()
                .map(Objects::toString)
                .toList();
    }
}
