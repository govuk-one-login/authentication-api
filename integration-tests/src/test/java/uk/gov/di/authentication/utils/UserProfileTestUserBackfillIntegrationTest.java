package uk.gov.di.authentication.utils;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;
import uk.gov.di.authentication.sharedtest.extensions.UserStoreExtension;
import uk.gov.di.authentication.utils.lambda.UserProfileTestUserBackfill;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class UserProfileTestUserBackfillIntegrationTest {
    private static final String VALUE_MISSING_EMAIL = "test-user1@test.com";
    private static final String STANDARD_USER_EMAIL = "test-user2@test.com";
    private static final String TEST_USER_EMAIL = "test-user3@test.com";

    private UserProfileTestUserBackfill handler;
    @RegisterExtension static UserStoreExtension userStoreExtension = new UserStoreExtension();

    @BeforeEach
    void setUp() {
        this.handler = new UserProfileTestUserBackfill();
    }

    @Test
    void shouldUpdateTheCorrectRows() {
        createTestData();
        handler.handleRequest();
        assertTestUserValueForEmail(VALUE_MISSING_EMAIL, "0");
        assertTestUserValueForEmail(STANDARD_USER_EMAIL, "0");
        assertTestUserValueForEmail(TEST_USER_EMAIL, "1");
    }

    private void createTestData() {
        userStoreExtension.signUp(VALUE_MISSING_EMAIL, "test-password1");
        userStoreExtension.signUp(STANDARD_USER_EMAIL, "test-password1");
        userStoreExtension.signUp(TEST_USER_EMAIL, "test-password1", new Subject(), true);

        Map<String, AttributeValue> keyToUpdate = keyFromEmail(VALUE_MISSING_EMAIL);
        var updateRequest =
                UpdateItemRequest.builder()
                        .tableName(UserStoreExtension.USER_PROFILE_TABLE)
                        .key(keyToUpdate)
                        .updateExpression("REMOVE testUser")
                        .build();
        userStoreExtension.getRawDynamoClient().updateItem(updateRequest);
    }

    @NotNull
    private static Map<String, AttributeValue> keyFromEmail(String email) {
        return Map.of(UserStoreExtension.EMAIL_FIELD, AttributeValue.builder().s(email).build());
    }

    private static void assertTestUserValueForEmail(String email, String testUser) {
        var value = getRawItemByEmail(email);
        assertEquals(AttributeValue.builder().n(testUser).build(), value.item().get("testUser"));
    }

    private static GetItemResponse getRawItemByEmail(String email) {
        GetItemRequest getItemRequest =
                GetItemRequest.builder()
                        .tableName(UserStoreExtension.USER_PROFILE_TABLE)
                        .key(keyFromEmail(email))
                        .build();
        return userStoreExtension.getRawDynamoClient().getItem(getItemRequest);
    }
}
