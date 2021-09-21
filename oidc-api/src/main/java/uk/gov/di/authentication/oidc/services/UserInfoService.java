package uk.gov.di.authentication.oidc.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.TokenStore;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.exceptions.UserInfoValidationException;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.TokenValidationService;

import java.text.ParseException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;

public class UserInfoService {

    private final RedisConnectionService redisConnectionService;
    private final AuthenticationService authenticationService;
    private final TokenValidationService tokenValidationService;
    private final DynamoClientService clientService;
    private static final String ACCESS_TOKEN_PREFIX = "ACCESS_TOKEN:";

    private static final Logger LOGGER = LoggerFactory.getLogger(UserInfoService.class);

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
        LOGGER.info("Processing UserInfo request");
        AccessToken accessToken;
        try {
            accessToken = AccessToken.parse(authorizationHeader, AccessTokenType.BEARER);
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            LOGGER.error("Unable to parse AccessToken", e);
            throw new UserInfoValidationException(
                    "Unable to parse AccessToken", BearerTokenError.INVALID_TOKEN);
        }
        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(accessToken.getValue());

            DefaultJWTClaimsVerifier defaultJWTClaimsVerifier =
                    new DefaultJWTClaimsVerifier(
                            null,
                            new HashSet<>(
                                    Arrays.asList("sub", "iat", "exp", "client_id", "scope")));
            try {
                defaultJWTClaimsVerifier.verify(signedJWT.getJWTClaimsSet(), null);
            } catch (BadJOSEException e) {
                LOGGER.error("Access Token was unabled to be processed", e);
                throw new UserInfoValidationException(
                        "Invalid Access Token", BearerTokenError.INVALID_TOKEN);
            }
            if (!tokenValidationService.validateAccessTokenSignature(accessToken)) {
                LOGGER.error("Unable to validate AccessToken signature");
                throw new UserInfoValidationException(
                        "Unable to validate AccessToken signature", BearerTokenError.INVALID_TOKEN);
            }
            String clientID = signedJWT.getJWTClaimsSet().getStringClaim("client_id");
            Optional<ClientRegistry> client = clientService.getClient(clientID);
            if (client.isEmpty()) {
                LOGGER.error("Client not found with given ClientID: {}", clientID);
                throw new UserInfoValidationException(
                        "Client not found with given ClientID", BearerTokenError.INVALID_TOKEN);
            }
            List<String> scopes = (List<String>) signedJWT.getJWTClaimsSet().getClaim("scope");
            if (!areScopesValid(scopes) || !client.get().getScopes().containsAll(scopes)) {
                LOGGER.error("Invalid Scopes: {}", scopes);
                throw new UserInfoValidationException("Invalid Scopes", OAuth2Error.INVALID_SCOPE);
            }
            String subject = signedJWT.getJWTClaimsSet().getSubject();
            Optional<TokenStore> accessTokenStore = getAccessTokenStore(clientID, subject);
            if (accessTokenStore.isEmpty()) {
                LOGGER.error("Access Token Store is empty");
                throw new UserInfoValidationException(
                        "Invalid Access Token", BearerTokenError.INVALID_TOKEN);
            }
            if (!accessTokenStore.get().getToken().equals(accessToken.getValue())) {
                LOGGER.error(
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
            LOGGER.error("Unable to parse AccessToken to SignedJWT", e);
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
        return userInfo;
    }

    private Optional<TokenStore> getAccessTokenStore(String clientId, String subjectId) {
        String result =
                redisConnectionService.getValue(ACCESS_TOKEN_PREFIX + clientId + "." + subjectId);
        try {
            return Optional.ofNullable(new ObjectMapper().readValue(result, TokenStore.class));
        } catch (JsonProcessingException | IllegalArgumentException e) {
            LOGGER.error("Error getting AccessToken from Redis");
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
