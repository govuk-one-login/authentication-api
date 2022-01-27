package uk.gov.di.authentication.oidc.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.entity.AccessTokenInfo;
import uk.gov.di.authentication.shared.entity.AccessTokenStore;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.exceptions.AccessTokenException;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.TokenValidationService;

import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class AccessTokenService {

    private static final Logger LOG = LogManager.getLogger(AccessTokenService.class);
    private final RedisConnectionService redisConnectionService;
    private final DynamoClientService clientService;
    private final TokenValidationService tokenValidationService;
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

    public AccessTokenInfo parse(String authorizationHeader) throws AccessTokenException {
        AccessToken accessToken;
        try {
            accessToken = AccessToken.parse(authorizationHeader, AccessTokenType.BEARER);
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            LOG.error("Unable to parse AccessToken");
            throw new AccessTokenException(
                    "Unable to parse AccessToken", BearerTokenError.INVALID_TOKEN);
        }
        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(accessToken.getValue());

            LocalDateTime localDateTime = LocalDateTime.now();
            Date currentDateTime = Date.from(localDateTime.atZone(ZoneId.of("UTC")).toInstant());
            if (DateUtils.isBefore(
                    signedJWT.getJWTClaimsSet().getExpirationTime(), currentDateTime, 0)) {
                LOG.error(
                        "Access Token has expired. Access Token expires at: {}. CurrentDateTime is: {}",
                        signedJWT.getJWTClaimsSet().getExpirationTime(),
                        currentDateTime);
                throw new AccessTokenException(
                        INVALID_ACCESS_TOKEN, BearerTokenError.INVALID_TOKEN);
            }
            if (!tokenValidationService.validateAccessTokenSignature(accessToken)) {
                LOG.error("Unable to validate AccessToken signature");
                throw new AccessTokenException(
                        "Unable to validate AccessToken signature", BearerTokenError.INVALID_TOKEN);
            }
            String clientID = signedJWT.getJWTClaimsSet().getStringClaim("client_id");
            Optional<ClientRegistry> client = clientService.getClient(clientID);

            attachLogFieldToLogs(CLIENT_ID, clientID);

            if (client.isEmpty()) {
                LOG.error("Client not found");
                throw new AccessTokenException("Client not found", BearerTokenError.INVALID_TOKEN);
            }
            List<String> scopes = (List<String>) signedJWT.getJWTClaimsSet().getClaim("scope");
            if (!areScopesValid(scopes) || !client.get().getScopes().containsAll(scopes)) {
                LOG.error("Invalid Scopes: {}", scopes);
                throw new AccessTokenException("Invalid Scopes", OAuth2Error.INVALID_SCOPE);
            }
            String subject = signedJWT.getJWTClaimsSet().getSubject();
            Optional<AccessTokenStore> accessTokenStore = getAccessTokenStore(clientID, subject);
            if (accessTokenStore.isEmpty()) {
                LOG.error(
                        "Access Token Store is empty. Access Token expires at: {}. CurrentDateTime is: {}",
                        signedJWT.getJWTClaimsSet().getExpirationTime(),
                        currentDateTime);
                throw new AccessTokenException(
                        INVALID_ACCESS_TOKEN, BearerTokenError.INVALID_TOKEN);
            }
            if (!accessTokenStore.get().getToken().equals(accessToken.getValue())) {
                LOG.error(
                        "Access Token in Access Token Store is different to Access Token sent in request");
                throw new AccessTokenException(
                        INVALID_ACCESS_TOKEN, BearerTokenError.INVALID_TOKEN);
            }
            return new AccessTokenInfo(accessTokenStore.get(), subject, scopes);
        } catch (ParseException e) {
            LOG.error("Unable to parse AccessToken to SignedJWT");
            throw new AccessTokenException(
                    "Unable to parse AccessToken to SignedJWT", BearerTokenError.INVALID_TOKEN);
        }
    }

    private Optional<AccessTokenStore> getAccessTokenStore(String clientId, String subjectId) {
        String result =
                redisConnectionService.getValue(ACCESS_TOKEN_PREFIX + clientId + "." + subjectId);
        try {
            return Optional.ofNullable(
                    new ObjectMapper().readValue(result, AccessTokenStore.class));
        } catch (JsonProcessingException | IllegalArgumentException e) {
            LOG.error("Error getting AccessToken from Redis");
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
}
