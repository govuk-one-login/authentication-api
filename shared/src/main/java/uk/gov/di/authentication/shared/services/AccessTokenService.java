package uk.gov.di.authentication.shared.services;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.token.AccessTokenStore;
import uk.gov.di.authentication.shared.exceptions.AccessTokenException;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

public class AccessTokenService extends BaseDynamoService<AccessTokenStore> {
    private static final Logger LOG = LogManager.getLogger(AccessTokenService.class);
    private final long timeToExist;

    public AccessTokenService(ConfigurationService configurationService) {
        super(AccessTokenStore.class, "access-token-store", configurationService);
        this.timeToExist = configurationService.getAccessTokenExpiry();
    }

    public void addAccessTokenStore(
            String accessToken,
            String subjectID,
            List<String> claims,
            boolean isNewAccount,
            String sectorIdentifier,
            Long passwordResetTime) {
        var tokenStore =
                get(accessToken)
                        .orElse(new AccessTokenStore())
                        .withAccessToken(accessToken)
                        .withSubjectID(subjectID)
                        .withClaims(claims)
                        .withUsed(false)
                        .withNewAccount(isNewAccount)
                        .withSectorIdentifier(sectorIdentifier)
                        .withTimeToExist(
                                NowHelper.nowPlus(timeToExist, ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond())
                        .withPasswordResetTime(passwordResetTime);
        update(tokenStore);
    }

    public Optional<AccessTokenStore> getAccessTokenStore(String accessToken) {
        return get(accessToken)
                .filter(t -> t.getTimeToExist() > NowHelper.now().toInstant().getEpochSecond());
    }

    public Optional<AccessTokenStore> setAccessTokenStoreUsed(String accessToken, boolean used) {
        return get(accessToken)
                .map(
                        ts -> {
                            ts.setUsed(used);
                            update(ts);
                            return ts;
                        });
    }

    public AccessToken getAccessTokenFromAuthorizationHeader(String authorizationHeader)
            throws AccessTokenException {
        try {
            return AccessToken.parse(authorizationHeader, AccessTokenType.BEARER);
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            LOG.warn("Unable to extract (opaque) bearer token");
            throw new AccessTokenException(
                    "Unable to extract (opaque) bearer token", BearerTokenError.INVALID_TOKEN);
        }
    }

    public Optional<AccessTokenStore> setAccessTokenTtlTestOnly(String accessToken, long newTtl) {
        return get(accessToken)
                .map(
                        ts -> {
                            ts.setTimeToExist(newTtl);
                            update(ts);
                            return ts;
                        });
    }
}
