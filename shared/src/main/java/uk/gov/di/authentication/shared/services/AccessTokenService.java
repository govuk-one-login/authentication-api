package uk.gov.di.authentication.shared.services;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.model.GetItemEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.authentication.shared.entity.token.AccessTokenStore;
import uk.gov.di.authentication.shared.exceptions.AccessTokenException;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.ACCESS_TOKEN_SERVICE_CONSISTENT_READ_QUERY_ATTEMPT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.ACCESS_TOKEN_SERVICE_CONSISTENT_READ_QUERY_SUCCESS;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.ACCESS_TOKEN_SERVICE_INITIAL_QUERY_ATTEMPT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.ACCESS_TOKEN_SERVICE_INITIAL_QUERY_SUCCESS;

public class AccessTokenService extends BaseDynamoService<AccessTokenStore> {
    private static final Logger LOG = LogManager.getLogger(AccessTokenService.class);
    private final long timeToExist;
    private CloudwatchMetricsService cloudwatchMetricsService;
    private ConfigurationService configurationService;

    public AccessTokenService(ConfigurationService configurationService) {
        super(AccessTokenStore.class, "access-token-store", configurationService);
        this.timeToExist = configurationService.getAccessTokenExpiry();
        this.configurationService = configurationService;
    }

    public AccessTokenService(
            ConfigurationService configurationService,
            CloudwatchMetricsService cloudwatchMetricsService) {
        this(configurationService);
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.configurationService = configurationService;
    }

    public AccessTokenService(
            CloudwatchMetricsService cloudwatchMetricsService,
            ConfigurationService configurationService,
            DynamoDbClient dynamoDbClient,
            DynamoDbTable<AccessTokenStore> dynamoDbTable,
            long timeToExist) {
        super(dynamoDbTable, dynamoDbClient);
        this.configurationService = configurationService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.timeToExist = timeToExist;
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

    @Override
    public Optional<AccessTokenStore> get(String partition) {
        Key partitionKey = Key.builder().partitionValue(partition).build();
        Optional<AccessTokenStore> accessTokenStore =
                Optional.ofNullable(dynamoTable.getItem(partitionKey));
        incrementCloudwatchCounter(ACCESS_TOKEN_SERVICE_INITIAL_QUERY_ATTEMPT.getValue());

        if (accessTokenStore.isPresent()) {
            incrementCloudwatchCounter(ACCESS_TOKEN_SERVICE_INITIAL_QUERY_SUCCESS.getValue());
            return accessTokenStore;
        } else {
            incrementCloudwatchCounter(
                    ACCESS_TOKEN_SERVICE_CONSISTENT_READ_QUERY_ATTEMPT.getValue());
            GetItemEnhancedRequest getItemEnhancedRequest =
                    GetItemEnhancedRequest.builder()
                            .key(k -> k.partitionValue(partition))
                            .consistentRead(true)
                            .build();
            accessTokenStore = Optional.ofNullable(dynamoTable.getItem(getItemEnhancedRequest));
            if (accessTokenStore.isPresent()) {
                incrementCloudwatchCounter(
                        ACCESS_TOKEN_SERVICE_CONSISTENT_READ_QUERY_SUCCESS.getValue());
            }
            return accessTokenStore;
        }
    }

    void incrementCloudwatchCounter(String metricName) {
        try {
            cloudwatchMetricsService.incrementCounter(metricName, Collections.emptyMap());
        } catch (Exception e) {
            LOG.warn("Unable to increment access token service cloudwatch counter", e);
        }
    }
}
