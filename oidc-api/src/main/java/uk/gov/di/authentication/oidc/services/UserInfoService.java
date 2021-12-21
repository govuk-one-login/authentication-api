package uk.gov.di.authentication.oidc.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.AccessTokenStore;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.exceptions.UserInfoValidationException;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.TokenValidationService;

import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.Optional;

public class UserInfoService {

    private final RedisConnectionService redisConnectionService;
    private final AuthenticationService authenticationService;
    private final TokenValidationService tokenValidationService;
    private final DynamoClientService clientService;
    private static final String ACCESS_TOKEN_PREFIX = "ACCESS_TOKEN:";

    private static final Logger LOG = LogManager.getLogger(UserInfoService.class);

    public UserInfoService(
            RedisConnectionService redisConnectionService,
            AuthenticationService authenticationService,
            TokenValidationService tokenValidationService,
            DynamoClientService clientService) {
        this.redisConnectionService = redisConnectionService;
        this.authenticationService = authenticationService;
        this.tokenValidationService = tokenValidationService;
        this.clientService = clientService;
    }

    public UserInfo processUserInfoRequest(String authorizationHeader)
            throws UserInfoValidationException {
        LOG.info("Processing UserInfo request");
        AccessToken accessToken;
        try {
            accessToken = AccessToken.parse(authorizationHeader, AccessTokenType.BEARER);
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            LOG.error("Unable to parse AccessToken");
            throw new UserInfoValidationException(
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
                throw new UserInfoValidationException(
                        "Invalid Access Token", BearerTokenError.INVALID_TOKEN);
            }
            if (!tokenValidationService.validateAccessTokenSignature(accessToken)) {
                LOG.error("Unable to validate AccessToken signature");
                throw new UserInfoValidationException(
                        "Unable to validate AccessToken signature", BearerTokenError.INVALID_TOKEN);
            }
            String clientID = signedJWT.getJWTClaimsSet().getStringClaim("client_id");
            Optional<ClientRegistry> client = clientService.getClient(clientID);
            if (client.isEmpty()) {
                LOG.error("Client not found with given ClientID: {}", clientID);
                throw new UserInfoValidationException(
                        "Client not found with given ClientID", BearerTokenError.INVALID_TOKEN);
            }
            List<String> scopes = (List<String>) signedJWT.getJWTClaimsSet().getClaim("scope");
            if (!areScopesValid(scopes) || !client.get().getScopes().containsAll(scopes)) {
                LOG.error("Invalid Scopes: {}", scopes);
                throw new UserInfoValidationException("Invalid Scopes", OAuth2Error.INVALID_SCOPE);
            }
            String subject = signedJWT.getJWTClaimsSet().getSubject();
            Optional<AccessTokenStore> accessTokenStore = getAccessTokenStore(clientID, subject);
            if (accessTokenStore.isEmpty()) {
                LOG.error(
                        "Access Token Store is empty. Access Token expires at: {}. CurrentDateTime is: {}",
                        signedJWT.getJWTClaimsSet().getExpirationTime(),
                        currentDateTime);
                throw new UserInfoValidationException(
                        "Invalid Access Token", BearerTokenError.INVALID_TOKEN);
            }
            if (!accessTokenStore.get().getToken().equals(accessToken.getValue())) {
                LOG.error(
                        "Access Token in Access Token Store is different to Access Token sent in request");
                throw new UserInfoValidationException(
                        "Invalid Access Token", BearerTokenError.INVALID_TOKEN);
            }
            deleteAccessTokenStore(clientID, subject);
            UserProfile userProfile =
                    authenticationService.getUserProfileFromSubject(
                            accessTokenStore.get().getInternalSubjectId());
            return populateUserInfo(userProfile, subject, scopes);
        } catch (ParseException e) {
            LOG.error("Unable to parse AccessToken to SignedJWT");
            throw new UserInfoValidationException(
                    "Unable to parse AccessToken to SignedJWT", BearerTokenError.INVALID_TOKEN);
        }
    }

    private UserInfo populateUserInfo(
            UserProfile userProfile, String subject, List<String> scopes) {
        UserInfo userInfo = new UserInfo(new Subject(subject));
        if (scopes.contains("email")) {
            userInfo.setEmailAddress(userProfile.getEmail());
            userInfo.setEmailVerified(userProfile.isEmailVerified());
        }
        if (scopes.contains("phone")) {
            userInfo.setPhoneNumber(userProfile.getPhoneNumber());
            userInfo.setPhoneNumberVerified(userProfile.isPhoneNumberVerified());
        }
        if (scopes.contains("govuk-account")) {
            userInfo.setClaim("legacy_subject_id", userProfile.getLegacySubjectID());
        }
        return userInfo;
    }

    private Optional<AccessTokenStore> getAccessTokenStore(String clientId, String subjectId) {
        String result =
                redisConnectionService.getValue(ACCESS_TOKEN_PREFIX + clientId + "." + subjectId);
        try {
            return Optional.ofNullable(
                    new ObjectMapper().readValue(result, AccessTokenStore.class));
        } catch (JsonProcessingException | IllegalArgumentException e) {
            LOG.error("Error getting AccessToken from Redis. ClientID: {}", clientId);
            return Optional.empty();
        }
    }

    private void deleteAccessTokenStore(String clientId, String subjectId) {
        redisConnectionService.deleteValue(ACCESS_TOKEN_PREFIX + clientId + "." + subjectId);
    }

    private boolean areScopesValid(List<String> scopes) {
        for (String scope : scopes) {
            if (ValidScopes.getAllValidScopes().stream().noneMatch((t) -> t.equals(scope))) {
                return false;
            }
        }
        return true;
    }
}
