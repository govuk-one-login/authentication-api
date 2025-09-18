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
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.entity.ValidScopes;
import uk.gov.di.orchestration.shared.exceptions.AccessTokenException;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.serialization.Json.JsonException;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.TokenValidationService;

import java.text.ParseException;
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
    private final Json objectMapper = SerializationService.getInstance();
    private static final String ACCESS_TOKEN_PREFIX = "ACCESS_TOKEN:";
    private static final String INVALID_ACCESS_TOKEN = "Invalid Access Token";

    public AccessTokenService(
            RedisConnectionService redisConnectionService,
            DynamoClientService clientService,
            TokenValidationService tokenValidationService) {
        this.redisConnectionService = redisConnectionService;
        this.clientService = clientService;
        this.tokenValidationService = tokenValidationService;
    }

    public AccessTokenInfo parse(String authorizationHeader, boolean identityEnabled)
            throws AccessTokenException {
        AccessToken accessToken;
        try {
            accessToken = AccessToken.parse(authorizationHeader, AccessTokenType.BEARER);
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            LOG.warn("Unable to parse AccessToken");
            throw new AccessTokenException(
                    "Unable to parse AccessToken", BearerTokenError.INVALID_TOKEN);
        }
        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(accessToken.getValue());

            LOG.info(
                    "Successfully processed UserInfo request with JWT ID of {}",
                    signedJWT.getJWTClaimsSet().getJWTID());

            // Check access token hasn't expired
            var currentDateTime = NowHelper.now();
            if (DateUtils.isBefore(
                    signedJWT.getJWTClaimsSet().getExpirationTime(), currentDateTime, 0)) {
                LOG.warn(
                        "Access Token has expired. Access Token expires at: {}. CurrentDateTime is: {}",
                        signedJWT.getJWTClaimsSet().getExpirationTime(),
                        currentDateTime);
                throw new AccessTokenException(
                        INVALID_ACCESS_TOKEN, BearerTokenError.INVALID_TOKEN);
            }

            // Validate access token signature
            if (!tokenValidationService.validateAccessTokenSignature(accessToken)) {
                LOG.warn("Unable to validate AccessToken signature");
                throw new AccessTokenException(
                        "Unable to validate AccessToken signature", BearerTokenError.INVALID_TOKEN);
            }

            // Get client ID from claimsSet and check against client registry
            var clientID = signedJWT.getJWTClaimsSet().getStringClaim("client_id");
            if (Objects.isNull(clientID)) {
                LOG.warn("ClientID is null");
                throw new AccessTokenException("ClientID is null", BearerTokenError.INVALID_TOKEN);
            }
            attachLogFieldToLogs(CLIENT_ID, clientID);
            var client = clientService.getClient(clientID).orElse(null);
            if (Objects.isNull(client)) {
                LOG.warn("Client not found");
                throw new AccessTokenException("Client not found", BearerTokenError.INVALID_TOKEN);
            }

            // Get scopes from claimsSet and check against client registry
            var scopes =
                    JSONArrayUtils.parse(
                                    new Gson()
                                            .toJson(signedJWT.getJWTClaimsSet().getClaim("scope")))
                            .stream()
                            .map(Objects::toString)
                            .toList();
            if (!areScopesValid(scopes) || !client.getScopes().containsAll(scopes)) {
                LOG.warn("Invalid Scopes: {}", scopes);
                throw new AccessTokenException("Invalid Scopes", OAuth2Error.INVALID_SCOPE);
            }

            // Get identity claims if applicable
            List<String> identityClaims = null;
            if (identityEnabled && client.isIdentityVerificationSupported()) {
                LOG.info("Identity is enabled AND client supports identity verification");
                identityClaims = getIdentityClaims(signedJWT.getJWTClaimsSet());
            }

            var subject = signedJWT.getJWTClaimsSet().getSubject();

            // Check token provided against token in database
            var accessTokenStore = getAccessTokenStore(clientID, subject);
            if (accessTokenStore.isEmpty()) {
                LOG.warn(
                        "Access Token Store is empty. Access Token expires at: {}. CurrentDateTime is: {}. JWTID in Access Token sent in request: {}",
                        signedJWT.getJWTClaimsSet().getExpirationTime(),
                        currentDateTime,
                        signedJWT.getJWTClaimsSet().getJWTID());
                throw new AccessTokenException(
                        INVALID_ACCESS_TOKEN, BearerTokenError.INVALID_TOKEN);
            }
            if (!accessTokenStore.get().getToken().equals(accessToken.getValue())) {
                LOG.warn(
                        "Access Token in Access Token Store is different to Access Token sent in request");
                var storeJwtId =
                        SignedJWT.parse(accessTokenStore.get().getToken())
                                .getJWTClaimsSet()
                                .getJWTID();
                LOG.warn(
                        "JWTID in AccessTokenStore: {} compared to JWTID in Access Token sent in request: {}",
                        storeJwtId,
                        signedJWT.getJWTClaimsSet().getJWTID());
                throw new AccessTokenException(
                        INVALID_ACCESS_TOKEN, BearerTokenError.INVALID_TOKEN);
            }
            return new AccessTokenInfo(
                    accessTokenStore.get(), subject, scopes, identityClaims, client.getClientID());
        } catch (ParseException e) {
            LOG.warn("Unable to parse AccessToken to SignedJWT");
            throw new AccessTokenException(
                    "Unable to parse AccessToken to SignedJWT", BearerTokenError.INVALID_TOKEN);
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            LOG.warn("Unable to parse ClaimSet in AccessToken");
            throw new AccessTokenException(
                    "Unable to parse ClaimSet in AccessToken", BearerTokenError.INVALID_TOKEN);
        }
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

    private boolean areScopesValid(List<String> scopes) {
        for (String scope : scopes) {
            if (ValidScopes.getAllValidScopes().stream().noneMatch(t -> t.equals(scope))) {
                return false;
            }
        }
        return true;
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
}
