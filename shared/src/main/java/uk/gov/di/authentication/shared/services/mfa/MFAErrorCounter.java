package uk.gov.di.authentication.shared.services.mfa;

import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/* example usage:
// Initialize the counter
DynamoDbClient dynamoDb = DynamoDbClient.builder()
        .region(Region.US_EAST_1)
        .build();
        MFAErrorCounter counter = new MFAErrorCounter(dynamoDb, "YourTableName");

        // Example usage in authentication flow
        public void handleMFAAttempt(String userId, String mfaCode) {
            try {
                if (!validateMFACode(mfaCode)) {
                    counter.addMFAError(userId);
                    throw new InvalidMFAException("Invalid MFA code");
                }
                // MFA successful - continue with authentication
            } catch (AccountLockedException e) {
                // Handle locked account
                throw new AuthenticationException("Account is locked. Please contact support.");
            }
        }

        // Check if account is locked
        public boolean isAccountLocked(String userId) {
            MFAErrorCounter.MFACountResult result = counter.checkMFAErrorCount(userId);
            return result.isLocked();
        }
 */


public class MFAErrorCounter {
    private final DynamoDbClient dynamoDb;
    private final String tableName;
    private static final int MAX_ATTEMPTS = 6;
    private static final int TIME_WINDOW_MINUTES = 15;

    public MFAErrorCounter(DynamoDbClient dynamoDb, String tableName) {
        this.dynamoDb = dynamoDb;
        this.tableName = tableName;
    }

    public record MFACountResult(int totalCount, boolean isLocked) {}

    public MFACountResult checkMFAErrorCount(String userId) {
        // Calculate cutoff time for the window
        String cutoffTime = Instant.now()
                .minusSeconds(TIME_WINDOW_MINUTES * 60L)
                .toString();

        QueryRequest queryRequest = QueryRequest.builder()
                .tableName(tableName)
                .keyConditionExpression("userId = :userId AND begins_with(SK, :prefix)")
                .filterExpression("#timestamp > :cutoffTime")
                .expressionAttributeNames(Map.of("#timestamp", "timestamp"))
                .expressionAttributeValues(Map.of(
                        ":userId", AttributeValue.builder().s(userId).build(),
                        ":prefix", AttributeValue.builder().s("LOGIN#MFA#ERROR").build(),
                        ":cutoffTime", AttributeValue.builder().s(cutoffTime).build()
                ))
                .select(Select.COUNT)
                .build();

        QueryResponse response = dynamoDb.query(queryRequest);
        int count = response.count();

        return new MFACountResult(count, count >= MAX_ATTEMPTS);
    }

    public void addMFAError(String userId) throws AccountLockedException {
        // Check current count first
        MFACountResult currentCount = checkMFAErrorCount(userId);
        if (currentCount.isLocked()) {
            throw new AccountLockedException("Account is locked due to too many MFA attempts");
        }

        // Add new error record
        Instant now = Instant.now();
        // TTL set to 24 hours from now
        long ttl = now.plusSeconds(24 * 60 * 60).getEpochSecond();

        Map<String, AttributeValue> item = new HashMap<>();
        item.put("userId", AttributeValue.builder().s(userId).build());
        item.put("SK", AttributeValue.builder().s("LOGIN#MFA#ERROR#" + UUID.randomUUID()).build());
        item.put("timestamp", AttributeValue.builder().s(now.toString()).build());
        item.put("ttl", AttributeValue.builder().n(String.valueOf(ttl)).build());

        PutItemRequest putRequest = PutItemRequest.builder()
                .tableName(tableName)
                .item(item)
                .build();

        dynamoDb.putItem(putRequest);
    }

    public static class AccountLockedException extends Exception {
        public AccountLockedException(String message) {
            super(message);
        }
    }
}
