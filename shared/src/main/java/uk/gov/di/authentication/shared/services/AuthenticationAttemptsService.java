package uk.gov.di.authentication.shared.services;

import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;
import uk.gov.di.authentication.shared.entity.AuthenticationAttempts;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class AuthenticationAttemptsService extends BaseDynamoService<AuthenticationAttempts> {
    public AuthenticationAttemptsService(ConfigurationService configurationService) {
        super(AuthenticationAttempts.class, "authentication-attempt", configurationService);
    }

    public AuthenticationAttemptsService(
            DynamoDbClient dynamoDbClient, DynamoDbTable<AuthenticationAttempts> dynamoDbTable) {
        super(dynamoDbTable, dynamoDbClient);
    }

    private static final int MAX_ATTEMPTS = 3;

    public void createOrIncrementCount(
            String internalSubjectId, long ttl, JourneyType journeyType, CountType countType) {
        for (int attempt = 1; ; attempt++) {
            try {
                incrementOrCreateCount(internalSubjectId, ttl, journeyType, countType);
                return;
            } catch (ConditionalCheckFailedException e) {
                // Another request changed the record between our two writes
                if (attempt == MAX_ATTEMPTS) {
                    throw e;
                }
            }
        }
    }

    private void incrementOrCreateCount(
            String internalSubjectId, long ttl, JourneyType journeyType, CountType countType) {
        try {
            incrementCountIfLive(internalSubjectId, journeyType, countType);
        } catch (ConditionalCheckFailedException e) {
            // The record is missing or expired so we create a fresh one
            createOrResetCountIfMissingOrExpired(internalSubjectId, ttl, journeyType, countType);
        }
    }

    private void createOrResetCountIfMissingOrExpired(
            String internalSubjectId, long ttl, JourneyType journeyType, CountType countType) {
        var now = NowHelper.now().toInstant().getEpochSecond();
        var sortKey = buildSortKey(journeyType, countType);
        var updateItemRequest =
                UpdateItemRequest.builder()
                        .tableName(dynamoTable.tableName())
                        .key(
                                Map.ofEntries(
                                        Map.entry(
                                                "InternalSubjectId",
                                                AttributeValue.fromS(internalSubjectId)),
                                        Map.entry("SK", AttributeValue.fromS(sortKey))))
                        .conditionExpression("attribute_not_exists(#count) OR #ttl < :now")
                        .updateExpression("SET #count = :one, #ttl = :ttl")
                        .expressionAttributeNames(Map.of("#count", "Count", "#ttl", "TimeToLive"))
                        .expressionAttributeValues(
                                Map.ofEntries(
                                        Map.entry(":one", AttributeValue.fromN("1")),
                                        Map.entry(
                                                ":ttl", AttributeValue.fromN(String.valueOf(ttl))),
                                        Map.entry(
                                                ":now", AttributeValue.fromN(String.valueOf(now)))))
                        .build();
        update(updateItemRequest);
    }

    private void incrementCountIfLive(
            String internalSubjectId, JourneyType journeyType, CountType countType) {
        var now = NowHelper.now().toInstant().getEpochSecond();
        var sortKey = buildSortKey(journeyType, countType);
        var updateItemRequest =
                UpdateItemRequest.builder()
                        .tableName(dynamoTable.tableName())
                        .key(
                                Map.ofEntries(
                                        Map.entry(
                                                "InternalSubjectId",
                                                AttributeValue.fromS(internalSubjectId)),
                                        Map.entry("SK", AttributeValue.fromS(sortKey))))
                        .conditionExpression("attribute_exists(#count) AND #ttl >= :now")
                        .updateExpression("SET #count = #count + :one")
                        .expressionAttributeNames(Map.of("#count", "Count", "#ttl", "TimeToLive"))
                        .expressionAttributeValues(
                                Map.ofEntries(
                                        Map.entry(":one", AttributeValue.fromN("1")),
                                        Map.entry(
                                                ":now", AttributeValue.fromN(String.valueOf(now)))))
                        .build();
        update(updateItemRequest);
    }

    public int getCount(String internalSubjectId, JourneyType journeyType, CountType countType) {
        long currentTimestamp = NowHelper.now().toInstant().getEpochSecond();
        var authenticationAttemptRecord =
                get(internalSubjectId, buildSortKey(journeyType, countType))
                        .filter(t -> t.getTimeToLive() > currentTimestamp);
        if (authenticationAttemptRecord.isEmpty()) {
            return 0;
        }

        int count = authenticationAttemptRecord.get().getCount();

        // TODO remove temporary ZDD measure to sum deprecated count types
        if (countType.equals(CountType.ENTER_MFA_CODE)) {
            count +=
                    get(internalSubjectId, buildSortKey(journeyType, CountType.ENTER_SMS_CODE))
                                    .filter(t -> t.getTimeToLive() > currentTimestamp)
                                    .map(AuthenticationAttempts::getCount)
                                    .orElse(0)
                            + get(
                                            internalSubjectId,
                                            buildSortKey(
                                                    journeyType, CountType.ENTER_AUTH_APP_CODE))
                                    .filter(t -> t.getTimeToLive() > currentTimestamp)
                                    .map(AuthenticationAttempts::getCount)
                                    .orElse(0);
        }

        return count;
    }

    public Map<CountType, Integer> getCountsByJourneyForIdentifiers(
            List<String> identifiers, JourneyType journeyType) {
        Map<CountType, Integer> results = new EnumMap<>(CountType.class);
        var identifierList = identifiers.stream().filter(Objects::nonNull).distinct().toList();
        Arrays.stream(CountType.values())
                // TODO remove temporary ZDD measure to sum deprecated count types
                .filter(t -> t != CountType.ENTER_SMS_CODE && t != CountType.ENTER_AUTH_APP_CODE)
                .forEach(
                        countType -> {
                            var count =
                                    identifierList.stream()
                                            .mapToInt(
                                                    identifier ->
                                                            getCount(
                                                                    identifier,
                                                                    journeyType,
                                                                    countType))
                                            .sum();
                            if (count > 0) {
                                results.put(countType, count);
                            }
                        });

        return results;
    }

    public Map<CountType, Integer> getCountsByJourney(
            String internalSubjectId, JourneyType journeyType) {
        return getCountsByJourneyForIdentifiers(Arrays.asList(internalSubjectId), journeyType);
    }

    // This should only be used in specific journeys (e.g. reauth) where it's possible that a
    // non-logged in user
    // can go through a journey, and have counts initially stored against a pairwise id
    public Map<CountType, Integer> getCountsByJourneyForSubjectIdAndRpPairwiseId(
            String internalSubjectId, String rpPairwiseId, JourneyType journeyType) {
        return getCountsByJourneyForIdentifiers(
                Arrays.asList(internalSubjectId, rpPairwiseId), journeyType);
    }

    public void deleteCount(
            String internalSubjectId, JourneyType journeyType, CountType countType) {
        delete(internalSubjectId, buildSortKey(journeyType, countType));
    }

    public static String buildSortKey(JourneyType journeyType, CountType countType) {
        return journeyType.getValue() + "#" + countType.getValue() + "#" + "Count";
    }

    private boolean isTTLExpired(long ttl) {
        return (NowHelper.now().toInstant().getEpochSecond() > ttl);
    }
}
