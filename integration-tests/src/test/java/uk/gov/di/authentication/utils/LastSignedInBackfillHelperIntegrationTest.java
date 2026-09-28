package uk.gov.di.authentication.utils;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.extensions.LastSignedInTrackerExtension;
import uk.gov.di.authentication.sharedtest.extensions.UserStoreExtension;
import uk.gov.di.authentication.utils.entity.LastSignedInBackfillRequest;
import uk.gov.di.authentication.utils.entity.LastSignedInBackfillResponse;
import uk.gov.di.authentication.utils.lambda.LastSignedInBackfillHandler;

import java.net.URI;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.utils.helpers.LastSignedInBackfillHelper.buildConditionalUpdateRequest;

class LastSignedInBackfillHelperIntegrationTest {

    private static final String DYNAMO_ENDPOINT =
            System.getenv().getOrDefault("DYNAMO_ENDPOINT", "http://localhost:8000");
    private static final String REGION = System.getenv().getOrDefault("AWS_REGION", "eu-west-2");
    private static final String USER_PROFILE_TABLE = "local-user-profile";

    @RegisterExtension
    protected static final UserStoreExtension userStore = new UserStoreExtension();

    @RegisterExtension
    protected static final LastSignedInTrackerExtension trackerStore =
            new LastSignedInTrackerExtension();

    private final DynamoDbClient dynamoDbClient =
            DynamoDbClient.builder()
                    .credentialsProvider(DefaultCredentialsProvider.builder().build())
                    .region(Region.of(REGION))
                    .endpointOverride(URI.create(DYNAMO_ENDPOINT))
                    .build();

    @Test
    void shouldBackfillLastSignedInForExistingUserWithNoLastSignedIn() {
        userStore.signUp("user1@example.com", "password-1", new Subject());

        assertNull(getProfileAttribute("user1@example.com", UserProfile.ATTRIBUTE_LAST_SIGNED_IN));

        dynamoDbClient.updateItem(
                buildConditionalUpdateRequest(
                        USER_PROFILE_TABLE, "user1@example.com", "2025-06-15T10:00:00.000Z"));

        assertEquals(
                "2025-06-15T10:00:00.000Z",
                getProfileAttribute("user1@example.com", UserProfile.ATTRIBUTE_LAST_SIGNED_IN));
    }

    @Test
    void shouldUpdateLastSignedInWhenTrackerTimestampIsNewer() {
        userStore.signUp("user2@example.com", "password-1", new Subject());

        dynamoDbClient.updateItem(
                buildConditionalUpdateRequest(
                        USER_PROFILE_TABLE, "user2@example.com", "2025-01-01T00:00:00.000Z"));

        dynamoDbClient.updateItem(
                buildConditionalUpdateRequest(
                        USER_PROFILE_TABLE, "user2@example.com", "2025-06-15T10:00:00.000Z"));

        assertEquals(
                "2025-06-15T10:00:00.000Z",
                getProfileAttribute("user2@example.com", UserProfile.ATTRIBUTE_LAST_SIGNED_IN));
    }

    @Test
    void shouldNotOverwriteLastSignedInWhenTrackerTimestampIsOlder() {
        userStore.signUp("user3@example.com", "password-1", new Subject());

        dynamoDbClient.updateItem(
                buildConditionalUpdateRequest(
                        USER_PROFILE_TABLE, "user3@example.com", "2025-06-15T10:00:00.000Z"));

        var olderRequest =
                buildConditionalUpdateRequest(
                        USER_PROFILE_TABLE, "user3@example.com", "2025-01-01T00:00:00.000Z");

        assertThrows(
                ConditionalCheckFailedException.class,
                () -> dynamoDbClient.updateItem(olderRequest));

        assertEquals(
                "2025-06-15T10:00:00.000Z",
                getProfileAttribute("user3@example.com", UserProfile.ATTRIBUTE_LAST_SIGNED_IN));
    }

    @Test
    void shouldNotOverwriteLastSignedInWhenTrackerTimestampIsEqual() {
        userStore.signUp("user4@example.com", "password-1", new Subject());

        dynamoDbClient.updateItem(
                buildConditionalUpdateRequest(
                        USER_PROFILE_TABLE, "user4@example.com", "2025-06-15T10:00:00.000Z"));

        var sameRequest =
                buildConditionalUpdateRequest(
                        USER_PROFILE_TABLE, "user4@example.com", "2025-06-15T10:00:00.000Z");

        assertThrows(
                ConditionalCheckFailedException.class,
                () -> dynamoDbClient.updateItem(sameRequest));

        assertEquals(
                "2025-06-15T10:00:00.000Z",
                getProfileAttribute("user4@example.com", UserProfile.ATTRIBUTE_LAST_SIGNED_IN));
    }

    @Test
    void shouldNotCreatePartialItemWhenNoUserProfileExists() {
        assertFalse(getUserProfile("tracker-orphan@example.com").hasItem());

        var orphanRequest =
                buildConditionalUpdateRequest(
                        USER_PROFILE_TABLE,
                        "tracker-orphan@example.com",
                        "2025-06-15T10:00:00.000Z");

        assertThrows(
                ConditionalCheckFailedException.class,
                () -> dynamoDbClient.updateItem(orphanRequest));

        assertFalse(getUserProfile("tracker-orphan@example.com").hasItem());
    }

    @Test
    void shouldBeIdempotentWhenRunTwiceOnSameData() {
        userStore.signUp("idempotent@example.com", "password-1", new Subject());

        dynamoDbClient.updateItem(
                buildConditionalUpdateRequest(
                        USER_PROFILE_TABLE, "idempotent@example.com", "2025-06-15T10:00:00.000Z"));

        var duplicateRequest =
                buildConditionalUpdateRequest(
                        USER_PROFILE_TABLE, "idempotent@example.com", "2025-06-15T10:00:00.000Z");

        assertThrows(
                ConditionalCheckFailedException.class,
                () -> dynamoDbClient.updateItem(duplicateRequest));

        assertEquals(
                "2025-06-15T10:00:00.000Z",
                getProfileAttribute(
                        "idempotent@example.com", UserProfile.ATTRIBUTE_LAST_SIGNED_IN));
    }

    @Test
    void shouldNotCorruptExistingProfileAttributes() {
        userStore.signUp("preserve@example.com", "password-1", new Subject("subject-123"));

        GetItemResponse before = getUserProfile("preserve@example.com");
        String subjectIdBefore = before.item().get(UserProfile.ATTRIBUTE_SUBJECT_ID).s();

        dynamoDbClient.updateItem(
                buildConditionalUpdateRequest(
                        USER_PROFILE_TABLE, "preserve@example.com", "2025-06-15T10:00:00.000Z"));

        GetItemResponse after = getUserProfile("preserve@example.com");
        assertEquals(subjectIdBefore, after.item().get(UserProfile.ATTRIBUTE_SUBJECT_ID).s());
        assertEquals(
                "2025-06-15T10:00:00.000Z",
                after.item().get(UserProfile.ATTRIBUTE_LAST_SIGNED_IN).s());
        assertTrue(after.item().containsKey(UserProfile.ATTRIBUTE_CREATED));
    }

    @Test
    void shouldHandleTimestampsWithAndWithoutZSuffix() {
        userStore.signUp("zsuffix@example.com", "password-1", new Subject());

        dynamoDbClient.updateItem(
                buildConditionalUpdateRequest(
                        USER_PROFILE_TABLE, "zsuffix@example.com", "2025-06-15T10:00:00.000000"));

        assertEquals(
                "2025-06-15T10:00:00.000000",
                getProfileAttribute("zsuffix@example.com", UserProfile.ATTRIBUTE_LAST_SIGNED_IN));

        dynamoDbClient.updateItem(
                buildConditionalUpdateRequest(
                        USER_PROFILE_TABLE, "zsuffix@example.com", "2025-06-15T10:00:00.000000Z"));

        assertEquals(
                "2025-06-15T10:00:00.000000Z",
                getProfileAttribute("zsuffix@example.com", UserProfile.ATTRIBUTE_LAST_SIGNED_IN));
    }

    @Test
    void shouldProcessEndToEndWithHandlerScanningTrackerTable() {
        userStore.signUp("handler-user1@example.com", "password-1", new Subject());
        userStore.signUp("handler-user2@example.com", "password-1", new Subject());

        trackerStore.addTrackerItem("handler-user1@example.com", "2025-03-01T00:00:00.000Z");
        trackerStore.addTrackerItem("handler-user2@example.com", "2025-04-01T00:00:00.000Z");
        trackerStore.addTrackerItem("handler-orphan@example.com", "2025-05-01T00:00:00.000Z");

        LastSignedInBackfillResponse response =
                createHandler()
                        .handleRequest(
                                new LastSignedInBackfillRequest(null, null, null, null, null));

        assertEquals(3, response.processedCount());
        assertEquals(2, response.updatedCount());
        assertEquals(1, response.skippedCount());

        assertEquals(
                "2025-03-01T00:00:00.000Z",
                getProfileAttribute(
                        "handler-user1@example.com", UserProfile.ATTRIBUTE_LAST_SIGNED_IN));
        assertEquals(
                "2025-04-01T00:00:00.000Z",
                getProfileAttribute(
                        "handler-user2@example.com", UserProfile.ATTRIBUTE_LAST_SIGNED_IN));
        assertFalse(getUserProfile("handler-orphan@example.com").hasItem());
    }

    @Test
    void shouldSkipTrackerItemsWithMissingFieldsEndToEnd() {
        userStore.signUp("valid@example.com", "password-1", new Subject());

        trackerStore.addTrackerItem("valid@example.com", "2025-06-01T00:00:00.000Z");
        trackerStore.addTrackerItemWithoutEmail("2025-06-01T00:00:00.000Z");
        trackerStore.addTrackerItemWithoutUserLastActive("missing-timestamp@example.com");

        LastSignedInBackfillResponse response =
                createHandler()
                        .handleRequest(
                                new LastSignedInBackfillRequest(null, null, null, null, null));

        assertEquals(3, response.processedCount());
        assertEquals(1, response.updatedCount());
        assertEquals(2, response.skippedCount());

        assertEquals(
                "2025-06-01T00:00:00.000Z",
                getProfileAttribute("valid@example.com", UserProfile.ATTRIBUTE_LAST_SIGNED_IN));
    }

    @Test
    void shouldBeIdempotentEndToEndWhenHandlerRunTwice() {
        userStore.signUp("rerun@example.com", "password-1", new Subject());
        trackerStore.addTrackerItem("rerun@example.com", "2025-06-01T00:00:00.000Z");

        LastSignedInBackfillHandler handler = createHandler();

        LastSignedInBackfillResponse firstRun =
                handler.handleRequest(
                        new LastSignedInBackfillRequest(null, null, null, null, null));
        assertEquals(1, firstRun.updatedCount());
        assertEquals(0, firstRun.skippedCount());

        LastSignedInBackfillResponse secondRun =
                handler.handleRequest(
                        new LastSignedInBackfillRequest(null, null, null, null, null));
        assertEquals(0, secondRun.updatedCount());
        assertEquals(1, secondRun.skippedCount());

        assertEquals(
                "2025-06-01T00:00:00.000Z",
                getProfileAttribute("rerun@example.com", UserProfile.ATTRIBUTE_LAST_SIGNED_IN));
    }

    private LastSignedInBackfillHandler createHandler() {
        ConfigurationService config =
                new ConfigurationService() {
                    @Override
                    public String getEnvironment() {
                        return "local";
                    }

                    @Override
                    public String getLastSignedInBackfillTrackerTableName() {
                        return LastSignedInTrackerExtension.TRACKER_TABLE;
                    }

                    @Override
                    public int getLastSignedInBackfillParallelism() {
                        return 1;
                    }

                    @Override
                    public int getLastSignedInBackfillTotalSegments() {
                        return 1;
                    }

                    @Override
                    public int getLastSignedInBackfillMaxItemsPerSegment() {
                        return 100;
                    }

                    @Override
                    public long getLastSignedInBackfillPauseBetweenInvocationsMs() {
                        return 0;
                    }

                    @Override
                    public String getLastSignedInBackfillLambdaName() {
                        return "unused";
                    }

                    @Override
                    public int getLastSignedInBackfillMaxInvocations() {
                        return 1;
                    }
                };

        return new LastSignedInBackfillHandler(config, dynamoDbClient, null);
    }

    private String getProfileAttribute(String email, String attributeName) {
        GetItemResponse response = getUserProfile(email);
        if (!response.hasItem() || !response.item().containsKey(attributeName)) {
            return null;
        }
        return response.item().get(attributeName).s();
    }

    private GetItemResponse getUserProfile(String email) {
        return dynamoDbClient.getItem(
                GetItemRequest.builder()
                        .tableName(USER_PROFILE_TABLE)
                        .key(Map.of(UserProfile.ATTRIBUTE_EMAIL, AttributeValue.fromS(email)))
                        .build());
    }
}
