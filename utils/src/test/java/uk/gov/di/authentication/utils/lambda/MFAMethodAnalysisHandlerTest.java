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

        mockPhoneNumberIndexScan(0, 0);

        List<Map<String, AttributeValue>> items = new ArrayList<>();
        mockCredentialsScan(items, 0);

        List<Map<String, AttributeValue>> requestKeys = new ArrayList<>();
        mockProfileBatchGetItem(requestKeys, items);

        var handler = new MFAMethodAnalysisHandler(configurationService, client);
        assertEquals(
                "MFAMethodAnalysis{countOfAuthAppUsersAssessed=0, countOfPhoneNumberUsersAssessed=0, countOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods=0, countOfUsersWithVerifiedPhoneNumber=0, attributeCombinationsForAuthAppUsersCount={}}",
                handler.handleRequest("", mock(Context.class)));
    }

    @Test
    void shouldFindTheNumberOfMatches() {
        when(configurationService.getEnvironment()).thenReturn("test");

        mockPhoneNumberIndexScan(0, 0);

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
                "MFAMethodAnalysis{countOfAuthAppUsersAssessed=%s, countOfPhoneNumberUsersAssessed=0, countOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods=0, countOfUsersWithVerifiedPhoneNumber=0, attributeCombinationsForAuthAppUsersCount={AttributeCombinations[authAppEnabled=empty, authAppMethodVerified=empty, phoneNumberVerified=empty]=%s}}"
                        .formatted(size, size),
                handler.handleRequest("", mock(Context.class)));
    }

    @Test
    void shouldAnalyseUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods() {
        when(configurationService.getEnvironment()).thenReturn("test");

        mockPhoneNumberIndexScan(0, 0);

        int size = 20;
        int denominator = 3;
        List<Map<String, AttributeValue>> credentialItems = new ArrayList<>();
        for (int i = 1; i < size + 1; i++) {
            Map<String, AttributeValue> item = new HashMap<>();
            item.put("Email", AttributeValue.builder().s(getTestEmail(i)).build());
            Map<String, AttributeValue> mfaMethodEntry = new HashMap<>();
            mfaMethodEntry.put(
                    "Enabled",
                    AttributeValue.builder().n(i % denominator == 0 ? "1" : "0").build());
            mfaMethodEntry.put(
                    "MethodVerified",
                    AttributeValue.builder().n(i % denominator == 0 ? "0" : "1").build());
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
                    AttributeValue.builder().n(i % denominator == 0 ? "0" : "1").build());
            profileItems.add(item);
        }
        mockProfileBatchGetItem(requestKeys, profileItems);

        var handler = new MFAMethodAnalysisHandler(configurationService, client);
        int expectedCount = (int) Math.floor((float) size / denominator);
        assertEquals(
                "MFAMethodAnalysis{countOfAuthAppUsersAssessed=%s, countOfPhoneNumberUsersAssessed=0, countOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods=%s, countOfUsersWithVerifiedPhoneNumber=0, attributeCombinationsForAuthAppUsersCount={AttributeCombinations[authAppEnabled=false, authAppMethodVerified=true, phoneNumberVerified=true]=%s, AttributeCombinations[authAppEnabled=true, authAppMethodVerified=false, phoneNumberVerified=false]=%s}}"
                        .formatted(size, expectedCount, size - expectedCount, expectedCount),
                handler.handleRequest("", mock(Context.class)));
    }

    @Test
    void shouldRetrievePhoneNumberVerifiedStats() {
        when(configurationService.getEnvironment()).thenReturn("test");

        mockPhoneNumberIndexScan(100, 90);

        List<Map<String, AttributeValue>> items = new ArrayList<>();
        mockCredentialsScan(items, 0);

        List<Map<String, AttributeValue>> requestKeys = new ArrayList<>();
        mockProfileBatchGetItem(requestKeys, items);

        var handler = new MFAMethodAnalysisHandler(configurationService, client);
        assertEquals(
                "MFAMethodAnalysis{countOfAuthAppUsersAssessed=0, countOfPhoneNumberUsersAssessed=100, countOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods=0, countOfUsersWithVerifiedPhoneNumber=90, attributeCombinationsForAuthAppUsersCount={}}",
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

    private void mockPhoneNumberIndexScan(int scanCount, int resultCount) {
        when(client.scan(
                        ScanRequest.builder()
                                .tableName("test-user-profile")
                                .indexName("PhoneNumberIndex")
                                .filterExpression("PhoneNumberVerified = :v")
                                .expressionAttributeValues(
                                        Map.of(":v", AttributeValue.builder().n("1").build()))
                                .exclusiveStartKey(null)
                                .build()))
                .thenReturn(
                        ScanResponse.builder().count(resultCount).scannedCount(scanCount).build());
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
