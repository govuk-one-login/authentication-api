package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.KeysAndAttributes;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MFAMethodAnalysisHandlerTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoDbClient client = mock(DynamoDbClient.class);

    @Test
    void shouldHandleZero() {
        when(configurationService.getEnvironment()).thenReturn("test");

        List<Map<String, AttributeValue>> items = new ArrayList<>();
        mockCredentialsScan(items, 0);

        List<Map<String, AttributeValue>> requestKeys = new ArrayList<>();
        mockProfileBatchGetItem(requestKeys, items);

        var handler = new MFAMethodAnalysisHandler(configurationService, client);
        assertEquals(
                "MFAMethodAnalysis{countOfUsersAssessed=0, countOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods=0}",
                handler.handleRequest("", mock(Context.class)));
    }

    @Test
    void shouldFindTheNumberOfMatches() {
        when(configurationService.getEnvironment()).thenReturn("test");

        int size = 100_123;
        List<Map<String, AttributeValue>> items = new ArrayList<>();
        for (int i = 1; i < size + 1; i++) {
            Map<String, AttributeValue> item = new HashMap<>();
            item.put("Email", AttributeValue.builder().s(getTestEmail(i)).build());
            items.add(item);
        }
        mockCredentialsScan(items, size);

        List<Map<String, AttributeValue>> requestKeys = new ArrayList<>();
        for (int i = 1; i < size + 1; i++) {
            Map<String, AttributeValue> key = new HashMap<>();
            key.put(
                    UserProfile.ATTRIBUTE_EMAIL,
                    AttributeValue.builder().s(getTestEmail(i)).build());
            requestKeys.add(key);

            if (i % 100 == 0) {
                mockProfileBatchGetItem(requestKeys, items.subList(i - 100, i));
                requestKeys = new ArrayList<>();
            }
        }

        if (!requestKeys.isEmpty()) {
            mockProfileBatchGetItem(requestKeys, items.subList(size - requestKeys.size(), size));
        }

        var handler = new MFAMethodAnalysisHandler(configurationService, client);
        assertEquals(
                "MFAMethodAnalysis{countOfUsersAssessed=%s, countOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods=0}"
                        .formatted(size),
                handler.handleRequest("", mock(Context.class)));
    }

    @Test
    void shouldCountUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods() {
        when(configurationService.getEnvironment()).thenReturn("test");

        int size = 20;
        List<Map<String, AttributeValue>> credentialItems = new ArrayList<>();
        for (int i = 1; i < size + 1; i++) {
            Map<String, AttributeValue> item = new HashMap<>();
            item.put("Email", AttributeValue.builder().s(getTestEmail(i)).build());
            Map<String, AttributeValue> mfaMethodEntry = new HashMap<>();
            mfaMethodEntry.put(
                    "Enabled", AttributeValue.builder().n(i % 3 == 0 ? "1" : "0").build());
            mfaMethodEntry.put(
                    "MethodVerified", AttributeValue.builder().n(i % 3 == 0 ? "0" : "1").build());
            AttributeValue mfaMethods =
                    AttributeValue.builder()
                            .l(AttributeValue.builder().m(mfaMethodEntry).build())
                            .build();
            item.put("MfaMethods", mfaMethods);
            credentialItems.add(item);
        }
        mockCredentialsScan(credentialItems, size);

        List<Map<String, AttributeValue>> requestKeys = new ArrayList<>();
        for (int i = 1; i < size + 1; i++) {
            Map<String, AttributeValue> key = new HashMap<>();
            key.put(
                    UserProfile.ATTRIBUTE_EMAIL,
                    AttributeValue.builder().s(getTestEmail(i)).build());
            requestKeys.add(key);
        }
        List<Map<String, AttributeValue>> profileItems = new ArrayList<>();
        for (int i = 1; i < size + 1; i++) {
            Map<String, AttributeValue> item = new HashMap<>();
            item.put("Email", AttributeValue.builder().s(getTestEmail(i)).build());
            item.put(
                    "PhoneNumberVerified",
                    AttributeValue.builder().n(i % 3 == 0 ? "0" : "1").build());
            profileItems.add(item);
        }
        mockProfileBatchGetItem(requestKeys, profileItems);

        var handler = new MFAMethodAnalysisHandler(configurationService, client);
        assertEquals(
                "MFAMethodAnalysis{countOfUsersAssessed=%s, countOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods=6}"
                        .formatted(size),
                handler.handleRequest("", mock(Context.class)));
    }

    private void mockCredentialsScan(List<Map<String, AttributeValue>> items, int size) {
        when(client.scan(
                        ScanRequest.builder()
                                .tableName("test-user-credentials")
                                .filterExpression("attribute_exists(MfaMethods)")
                                .projectionExpression("Email,MfaMethods")
                                .exclusiveStartKey(null)
                                .build()))
                .thenReturn(
                        ScanResponse.builder().items(items).count(size).scannedCount(size).build());
    }

    private void mockProfileBatchGetItem(
            List<Map<String, AttributeValue>> keys, List<Map<String, AttributeValue>> items) {
        Map<String, KeysAndAttributes> requestItems = new HashMap<>();
        requestItems.put(
                "test-user-profile",
                KeysAndAttributes.builder()
                        .keys(keys)
                        .projectionExpression("Email,PhoneNumberVerified")
                        .build());

        Map<String, List<Map<String, AttributeValue>>> responses = new HashMap<>();
        responses.put("test-user-profile", items);

        when(client.batchGetItem(BatchGetItemRequest.builder().requestItems(requestItems).build()))
                .thenReturn(BatchGetItemResponse.builder().responses(responses).build());
    }

    private String getTestEmail(int counter) {
        return "test-" + counter + "@example.com";
    }
}
