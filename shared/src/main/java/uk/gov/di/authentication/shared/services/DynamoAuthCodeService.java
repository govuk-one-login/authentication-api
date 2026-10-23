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
        return get(authCode)
                .filter(t -> t.getTimeToExist() > NowHelper.now().toInstant().getEpochSecond());
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
        var authCodeStore =
                new AuthCodeStore()
                        .withSubjectID(subjectID)
                        .withAuthCode(authCode)
                        .withClaims(claims)
                        .withHasBeenUsed(hasBeenUsed)
                        .withSectorIdentifier(sectorIdentifier)
                        .withIsNewAccount(isNewAccount)
                        .withTimeToExist(
                                NowHelper.nowPlus(timeToExist, ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond())
                        .withPasswordResetTime(passwordResetTime)
                        .withJourneyID(journeyId);

        put(authCodeStore);
    }

    public boolean markAuthCodeAsUsedIfUnused(String authCode) {
        var updateItemRequest =
                UpdateItemRequest.builder()
                        .tableName(dynamoTable.tableName())
                        .key(
                                Map.of(
                                        AuthCodeStore.ATTRIBUTE_AUTH_CODE,
                                        AttributeValue.fromS(authCode)))
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

        try {
            update(updateItemRequest);
            return true;
        } catch (ConditionalCheckFailedException e) {
            LOG.warn("Auth code not marked as used as it was already used or does not exist");
            return false;
        }
    }
}
