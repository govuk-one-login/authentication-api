package uk.gov.di.authentication.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;
import uk.gov.di.authentication.shared.entity.AuthCodeStore;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class DynamoAuthCodeService extends BaseDynamoService<AuthCodeStore> {

    private static final Logger LOG = LogManager.getLogger(DynamoAuthCodeService.class);

    private final long timeToExist;

    public DynamoAuthCodeService(ConfigurationService configurationService) {
        super(AuthCodeStore.class, "auth-code-store", configurationService);
        this.timeToExist = configurationService.getAuthCodeExpiry();
    }

    public Optional<AuthCodeStore> getAuthCodeStore(String authCode) {
        var authCodeStore = get(authCode);
        if (authCodeStore.isEmpty()) {
            return Optional.empty();
        }
        long now = NowHelper.now().toInstant().getEpochSecond();
        if (authCodeStore.get().getTimeToExist() <= now) {
            return Optional.empty();
        }
        return authCodeStore;
    }

    public void deleteAuthCode(String authCode) {
        delete(authCode);
    }

    public void saveAuthCode(
            String subjectID,
            String authCode,
            List<String> claims,
            boolean hasBeenUsed,
            String sectorIdentifier,
            boolean isNewAccount,
            Long passwordResetTime,
            String journeyId) {
        var authCodeStore = new AuthCodeStore();
        authCodeStore.setSubjectID(subjectID);
        authCodeStore.setAuthCode(authCode);
        authCodeStore.setClaims(claims);
        authCodeStore.setHasBeenUsed(hasBeenUsed);
        authCodeStore.setSectorIdentifier(sectorIdentifier);
        authCodeStore.setIsNewAccount(isNewAccount);
        long expiry =
                NowHelper.nowPlus(timeToExist, ChronoUnit.SECONDS).toInstant().getEpochSecond();
        authCodeStore.setTimeToExist(expiry);
        authCodeStore.setPasswordResetTime(passwordResetTime);
        authCodeStore.setJourneyID(journeyId);

        put(authCodeStore);
    }

    public boolean markAuthCodeAsUsedIfUnused(String authCode) {
        try {
            update(buildMarkAsUsedRequest(authCode));
            return true;
        } catch (ConditionalCheckFailedException e) {
            LOG.warn("Auth code not marked as used as it was already used or does not exist");
            return false;
        }
    }

    private UpdateItemRequest buildMarkAsUsedRequest(String authCode) {
        return UpdateItemRequest.builder()
                .tableName(dynamoTable.tableName())
                .key(Map.of(AuthCodeStore.ATTRIBUTE_AUTH_CODE, AttributeValue.fromS(authCode)))
                .updateExpression("SET #hasBeenUsed = :true")
                .conditionExpression("#hasBeenUsed = :false")
                .expressionAttributeNames(
                        Map.of("#hasBeenUsed", AuthCodeStore.ATTRIBUTE_HAS_BEEN_USED))
                .expressionAttributeValues(
                        Map.of(
                                ":true",
                                AttributeValue.fromBool(true),
                                ":false",
                                AttributeValue.fromBool(false)))
                .build();
    }
}
