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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
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
                "MFAMethodAnalysis{countOfAuthAppUsersAssessed=0, countOfPhoneNumberUsersAssessed=0, countOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods=0, countOfUsersWithVerifiedPhoneNumber=0, phoneDestinationCounts={}, attributeCombinationsForAuthAppUsersCount={}, countOfAccountsWithoutAnyMfaMethods=0, countOfUsersWithMfaMethodsMigrated=0, countOfUsersWithoutMfaMethodsMigrated=0, missingUserProfileCount=0, mfaMethodPriorityIdentifierCombinations={}, mfaMethodDetailsCombinations={}} User profile retrieval failures: userProfile items could not be retrieved for 0 accounts.",
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
                "MFAMethodAnalysis{countOfAuthAppUsersAssessed=%s, countOfPhoneNumberUsersAssessed=0, countOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods=0, countOfUsersWithVerifiedPhoneNumber=0, phoneDestinationCounts={}, attributeCombinationsForAuthAppUsersCount={AttributeCombinations[authAppEnabled=empty, authAppMethodVerified=empty, phoneNumberVerified=empty]=%s}, countOfAccountsWithoutAnyMfaMethods=%s, countOfUsersWithMfaMethodsMigrated=0, countOfUsersWithoutMfaMethodsMigrated=%s, missingUserProfileCount=0, mfaMethodPriorityIdentifierCombinations={MfaMethodPriorityCombination[methods=]=%s}, mfaMethodDetailsCombinations={[]=%s}} User profile retrieval failures: userProfile items could not be retrieved for 0 accounts."
                        .formatted(size, size, size, size, size, size),
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
            item.put("mfaMethodsMigrated", AttributeValue.builder().bool(false).build());
            profileItems.add(item);
        }
        mockProfileBatchGetItem(requestKeys, profileItems);

        var handler = new MFAMethodAnalysisHandler(configurationService, client);
        int expectedCount = (int) Math.floor((float) size / denominator);
        assertEquals(
                "MFAMethodAnalysis{countOfAuthAppUsersAssessed=%s, countOfPhoneNumberUsersAssessed=0, countOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods=%s, countOfUsersWithVerifiedPhoneNumber=0, phoneDestinationCounts={}, attributeCombinationsForAuthAppUsersCount={AttributeCombinations[authAppEnabled=false, authAppMethodVerified=true, phoneNumberVerified=true]=%s, AttributeCombinations[authAppEnabled=true, authAppMethodVerified=false, phoneNumberVerified=false]=%s}, countOfAccountsWithoutAnyMfaMethods=%s, countOfUsersWithMfaMethodsMigrated=0, countOfUsersWithoutMfaMethodsMigrated=%s, missingUserProfileCount=0, mfaMethodPriorityIdentifierCombinations={MfaMethodPriorityCombination[methods=absent_attribute]=%s}, mfaMethodDetailsCombinations={[MfaMethodDetails[priorityIdentifier=absent_attribute, mfaMethodType=absent_attribute]]=%s}} User profile retrieval failures: userProfile items could not be retrieved for 0 accounts."
                        .formatted(
                                size,
                                expectedCount,
                                size - expectedCount,
                                expectedCount,
                                expectedCount,
                                size,
                                size,
                                size),
                handler.handleRequest("", mock(Context.class)));
    }

    @Test
    void shouldRetrievePhoneNumberVerifiedStats() {
        when(configurationService.getEnvironment()).thenReturn("test");

        mockPhoneNumberAndUserCredentialScans(List.of(), 0, 0, List.of(), 90, 100);
        mockProfileBatchGetItem(new ArrayList<>(), List.of());

        var handler = new MFAMethodAnalysisHandler(configurationService, client);
        assertEquals(
                "MFAMethodAnalysis{countOfAuthAppUsersAssessed=0, countOfPhoneNumberUsersAssessed=100, countOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods=0, countOfUsersWithVerifiedPhoneNumber=90, phoneDestinationCounts={}, attributeCombinationsForAuthAppUsersCount={}, countOfAccountsWithoutAnyMfaMethods=0, countOfUsersWithMfaMethodsMigrated=0, countOfUsersWithoutMfaMethodsMigrated=0, missingUserProfileCount=0, mfaMethodPriorityIdentifierCombinations={}, mfaMethodDetailsCombinations={}} User profile retrieval failures: userProfile items could not be retrieved for 0 accounts.",
                handler.handleRequest("", mock(Context.class)));
    }

    @Test
    void shouldCountPhoneDestinationTypes() {
        when(configurationService.getEnvironment()).thenReturn("test");

        List<Map<String, AttributeValue>> phoneItems =
                List.of(
                        Map.of("PhoneNumber", AttributeValue.builder().s("+447777777777").build()),
                        Map.of("PhoneNumber", AttributeValue.builder().s("+447777777778").build()),
                        Map.of("PhoneNumber", AttributeValue.builder().s("+33777777777").build()),
                        Map.of("PhoneNumber", AttributeValue.builder().s("+447777777779").build()),
                        Map.of("PhoneNumber", AttributeValue.builder().s("+17777777777").build()),
                        Map.of("PhoneNumber", AttributeValue.builder().s("invalid").build()));

        mockPhoneNumberAndUserCredentialScans(
                List.of(), 0, 0, phoneItems, phoneItems.size(), phoneItems.size());
        mockProfileBatchGetItem(new ArrayList<>(), List.of());

        var handler = new MFAMethodAnalysisHandler(configurationService, client);
        assertEquals(
                "MFAMethodAnalysis{countOfAuthAppUsersAssessed=0, countOfPhoneNumberUsersAssessed=6, countOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods=0, countOfUsersWithVerifiedPhoneNumber=6, phoneDestinationCounts={DOMESTIC=3, UNKNOWN=1, INTERNATIONAL=2}, attributeCombinationsForAuthAppUsersCount={}, countOfAccountsWithoutAnyMfaMethods=0, countOfUsersWithMfaMethodsMigrated=0, countOfUsersWithoutMfaMethodsMigrated=0, missingUserProfileCount=0, mfaMethodPriorityIdentifierCombinations={}, mfaMethodDetailsCombinations={}} User profile retrieval failures: userProfile items could not be retrieved for 0 accounts.",
                handler.handleRequest("", mock(Context.class)));
    }

    @Test
    void shouldCountMfaMethodPriorityIdentifierCombinations() {
        when(configurationService.getEnvironment()).thenReturn("test");

        List<String> nullOnly = new ArrayList<>();
        nullOnly.add(null);

        List<String> backupAndNull = new ArrayList<>();
        backupAndNull.add("BACKUP");
        backupAndNull.add(null);

        List<Map<String, AttributeValue>> credentialItems =
                List.of(
                        createUserWithMfaMethods(1, List.of()),
                        createUserWithMfaMethods(2, List.of("DEFAULT")),
                        createUserWithMfaMethods(3, List.of("DEFAULT")),
                        createUserWithMfaMethods(4, List.of("DEFAULT", "BACKUP")),
                        createUserWithMfaMethods(5, List.of("BACKUP", "DEFAULT")),
                        createUserWithMfaMethods(6, nullOnly),
                        createUserWithMfaMethods(7, backupAndNull),
                        createUserWithMfaMethods(8, List.of("DEFAULT", "DEFAULT")),
                        createUserWithMfaMethods(9, backupAndNull));

        mockPhoneNumberAndUserCredentialScans(
                credentialItems, credentialItems.size(), credentialItems.size(), List.of(), 0, 0);

        List<Map<String, AttributeValue>> requestKeys = new ArrayList<>();
        List<Map<String, AttributeValue>> profileItems = new ArrayList<>();
        for (Map<String, AttributeValue> item : credentialItems) {
            String email = item.get("Email").s();
            requestKeys.add(Map.of("Email", AttributeValue.builder().s(email).build()));
            profileItems.add(Map.of("Email", AttributeValue.builder().s(email).build()));
        }
        mockProfileBatchGetItem(requestKeys, profileItems);

        var handler = new MFAMethodAnalysisHandler(configurationService, client);
        String result = handler.handleRequest("", mock(Context.class));

        assertTrue(result.contains("MfaMethodPriorityCombination[methods=]=1"));
        assertTrue(result.contains("MfaMethodPriorityCombination[methods=DEFAULT]=2"));
        assertTrue(result.contains("MfaMethodPriorityCombination[methods=DEFAULT,BACKUP]=1"));
        assertTrue(result.contains("MfaMethodPriorityCombination[methods=BACKUP,DEFAULT]=1"));
        assertTrue(result.contains("MfaMethodPriorityCombination[methods=absent_attribute]=1"));
        assertTrue(result.contains("MfaMethodPriorityCombination[methods=DEFAULT,DEFAULT]=1"));
        assertTrue(
                result.contains("MfaMethodPriorityCombination[methods=BACKUP,absent_attribute]=2"));
        assertTrue(
                result.contains(
                        "User profile retrieval failures: userProfile items could not be retrieved for 0 accounts."));
    }

    private void mockCredentialsScan(List<Map<String, AttributeValue>> items, int size) {
        mockPhoneNumberAndUserCredentialScans(items, size, size, List.of(), 0, 0);
    }

    private void mockPhoneNumberIndexScan(int scanCount, int resultCount) {
        mockPhoneNumberAndUserCredentialScans(List.of(), 0, 0, List.of(), resultCount, scanCount);
    }

    private void mockPhoneNumberAndUserCredentialScans(
            List<Map<String, AttributeValue>> credentialItems,
            int credentialCount,
            int credentialScannedCount,
            List<Map<String, AttributeValue>> phoneItems,
            int phoneCount,
            int phoneScannedCount) {
        when(client.scan(any(ScanRequest.class)))
                .thenAnswer(
                        invocation -> {
                            ScanRequest request = invocation.getArgument(0);
                            if ("PhoneNumberIndex".equals(request.indexName())) {
                                return ScanResponse.builder()
                                        .items(phoneItems)
                                        .count(phoneCount)
                                        .scannedCount(phoneScannedCount)
                                        .build();
                            }

                            return ScanResponse.builder()
                                    .items(credentialItems)
                                    .count(credentialCount)
                                    .scannedCount(credentialScannedCount)
                                    .build();
                        });
    }

    private void mockProfileBatchGetItem(
            List<Map<String, AttributeValue>> keys, List<Map<String, AttributeValue>> items) {
        Map<String, KeysAndAttributes> requestItems = new HashMap<>();
        requestItems.put(
                "test-user-profile",
                KeysAndAttributes.builder()
                        .keys(keys)
                        .projectionExpression("Email,PhoneNumberVerified,mfaMethodsMigrated")
                        .build());

        Map<String, List<Map<String, AttributeValue>>> responses = new HashMap<>();
        responses.put("test-user-profile", items);

        when(client.batchGetItem(BatchGetItemRequest.builder().requestItems(requestItems).build()))
                .thenReturn(BatchGetItemResponse.builder().responses(responses).build());
    }

    private Map<String, AttributeValue> createUserWithMfaMethods(
            int userIndex, List<String> priorities) {
        Map<String, AttributeValue> user = new HashMap<>();
        user.put("Email", AttributeValue.builder().s(getTestEmail(userIndex)).build());

        if (priorities != null && !priorities.isEmpty()) {
            List<AttributeValue> methods = new ArrayList<>();
            for (String priority : priorities) {
                Map<String, AttributeValue> method = new HashMap<>();
                if (priority != null) {
                    method.put("PriorityIdentifier", AttributeValue.builder().s(priority).build());
                }
                methods.add(AttributeValue.builder().m(method).build());
            }
            user.put("MfaMethods", AttributeValue.builder().l(methods).build());
        }

        return user;
    }

    @Test
    void shouldCalculateMissingProfileCountCorrectly() {
        when(configurationService.getEnvironment()).thenReturn("test");
        mockPhoneNumberIndexScan(0, 0);

        // Add 10 userCredential items.
        List<Map<String, AttributeValue>> credentialItems = new ArrayList<>();
        for (int i = 1; i <= 10; i++) {
            credentialItems.add(
                    Map.of("Email", AttributeValue.builder().s(getTestEmail(i)).build()));
        }
        mockCredentialsScan(credentialItems, credentialItems.size());

        // Only return 7 userProfile items.
        List<Map<String, AttributeValue>> profileItems = credentialItems.subList(0, 7);
        mockProfileBatchGetItem(credentialItems, profileItems);

        var handler = new MFAMethodAnalysisHandler(configurationService, client);
        String result = handler.handleRequest("", mock(Context.class));

        assertTrue(
                result.contains(
                        "User profile retrieval failures: userProfile items could not be retrieved for 3 accounts."));
        assertTrue(result.contains("missingUserProfileCount=3"));
    }

    @Test
    void shouldTrackMfaMethodDetailsCombinations() {
        when(configurationService.getEnvironment()).thenReturn("test");
        mockPhoneNumberIndexScan(0, 0);

        List<Map<String, AttributeValue>> credentialItems =
                List.of(
                        createUserWithMfaMethodDetails(1, "DEFAULT", "AUTH_APP"),
                        createUserWithMfaMethodDetails(2, "BACKUP", "SMS"),
                        createUserWithMfaMethodDetails(3, null, "AUTH_APP"), // absent priority
                        createUserWithMfaMethodDetails(4, "DEFAULT", null), // absent type
                        createUserWithMfaMethodDetails(5, "DEFAULT", "AUTH_APP"), // duplicate
                        createUserWithMfaMethodDetails(6, "null", "AUTH_APP"));

        mockCredentialsScan(credentialItems, credentialItems.size());
        mockProfileBatchGetItem(
                createKeysFromCredentials(credentialItems),
                createProfilesFromCredentials(credentialItems));

        var handler = new MFAMethodAnalysisHandler(configurationService, client);
        String result = handler.handleRequest("", mock(Context.class));

        assertTrue(
                result.contains(
                        "[MfaMethodDetails[priorityIdentifier=DEFAULT, mfaMethodType=AUTH_APP]]=2"));
        assertTrue(
                result.contains(
                        "[MfaMethodDetails[priorityIdentifier=BACKUP, mfaMethodType=SMS]]=1"));
        assertTrue(
                result.contains(
                        "[MfaMethodDetails[priorityIdentifier=absent_attribute, mfaMethodType=AUTH_APP]]=1"));
        assertTrue(
                result.contains(
                        "[MfaMethodDetails[priorityIdentifier=DEFAULT, mfaMethodType=absent_attribute]]=1"));
        assertTrue(
                result.contains(
                        "[MfaMethodDetails[priorityIdentifier=null, mfaMethodType=AUTH_APP]]=1"));
    }

    @Test
    void shouldHandleMultipleMfaMethodsPerUser() {
        when(configurationService.getEnvironment()).thenReturn("test");
        mockPhoneNumberIndexScan(0, 0);

        List<Map<String, AttributeValue>> credentialItems =
                List.of(
                        createUserWithMultipleMfaMethods(
                                1,
                                List.of(
                                        Map.of(
                                                "PriorityIdentifier",
                                                "DEFAULT",
                                                "MfaMethodType",
                                                "AUTH_APP"),
                                        Map.of(
                                                "PriorityIdentifier",
                                                "BACKUP",
                                                "MfaMethodType",
                                                "SMS"))),
                        createUserWithMultipleMfaMethods(
                                2, List.of(Map.of("MfaMethodType", "AUTH_APP"))) // missing priority
                        );

        mockCredentialsScan(credentialItems, credentialItems.size());
        mockProfileBatchGetItem(
                createKeysFromCredentials(credentialItems),
                createProfilesFromCredentials(credentialItems));

        var handler = new MFAMethodAnalysisHandler(configurationService, client);
        String result = handler.handleRequest("", mock(Context.class));

        assertTrue(
                result.contains(
                        "[MfaMethodDetails[priorityIdentifier=DEFAULT, mfaMethodType=AUTH_APP], MfaMethodDetails[priorityIdentifier=BACKUP, mfaMethodType=SMS]]=1"));
        assertTrue(
                result.contains(
                        "[MfaMethodDetails[priorityIdentifier=absent_attribute, mfaMethodType=AUTH_APP]]=1"));
    }

    private Map<String, AttributeValue> createUserWithMfaMethodDetails(
            int userIndex, String priority, String type) {
        Map<String, String> method = new HashMap<>();

        if (priority != null) {
            method.put("PriorityIdentifier", priority);
        }
        if (type != null) {
            method.put("MfaMethodType", type);
        }

        return createUserWithMultipleMfaMethods(userIndex, List.of(method));
    }

    private Map<String, AttributeValue> createUserWithMultipleMfaMethods(
            int userIndex, List<Map<String, String>> methods) {
        Map<String, AttributeValue> user = new HashMap<>();
        user.put("Email", AttributeValue.builder().s(getTestEmail(userIndex)).build());

        List<AttributeValue> methodList = new ArrayList<>();
        for (Map<String, String> methodData : methods) {
            Map<String, AttributeValue> method = new HashMap<>();
            methodData.forEach(
                    (key, value) -> method.put(key, AttributeValue.builder().s(value).build()));
            methodList.add(AttributeValue.builder().m(method).build());
        }

        user.put("MfaMethods", AttributeValue.builder().l(methodList).build());
        return user;
    }

    private List<Map<String, AttributeValue>> createKeysFromCredentials(
            List<Map<String, AttributeValue>> credentialItems) {
        return credentialItems.stream()
                .map(item -> Map.of("Email", item.get("Email")))
                .collect(ArrayList::new, ArrayList::add, ArrayList::addAll);
    }

    private List<Map<String, AttributeValue>> createProfilesFromCredentials(
            List<Map<String, AttributeValue>> credentialItems) {
        return credentialItems.stream()
                .map(
                        item -> {
                            Map<String, AttributeValue> profile = new HashMap<>();
                            profile.put("Email", item.get("Email"));
                            profile.put(
                                    "mfaMethodsMigrated",
                                    AttributeValue.builder().bool(true).build());
                            return profile;
                        })
                .collect(ArrayList::new, ArrayList::add, ArrayList::addAll);
    }

    @Test
    void shouldCountAccountsWithoutMfaMethodsForMigratedUsers() {
        when(configurationService.getEnvironment()).thenReturn("test");
        mockPhoneNumberIndexScan(0, 0);

        List<Map<String, AttributeValue>> credentialItems =
                List.of(
                        createUserWithMfaMethods(1, List.of()), // No MFA methods
                        createUserWithMfaMethods(2, List.of("DEFAULT")), // Has MFA method
                        createUserWithMfaMethods(3, List.of()) // No MFA methods
                        );

        mockCredentialsScan(credentialItems, credentialItems.size());

        List<Map<String, AttributeValue>> profileItems =
                List.of(
                        createProfileWithMigrationStatus(1, true, false), // Migrated, no MFA
                        createProfileWithMigrationStatus(2, true, false), // Migrated, has MFA
                        createProfileWithMigrationStatus(3, true, false) // Migrated, no MFA
                        );

        mockProfileBatchGetItem(createKeysFromCredentials(credentialItems), profileItems);

        var handler = new MFAMethodAnalysisHandler(configurationService, client);
        String result = handler.handleRequest("", mock(Context.class));

        assertTrue(result.contains("countOfAccountsWithoutAnyMfaMethods=2"));
        assertTrue(result.contains("countOfUsersWithMfaMethodsMigrated=3"));
        assertTrue(result.contains("countOfUsersWithoutMfaMethodsMigrated=0"));
    }

    @Test
    void shouldCountAccountsWithoutMfaMethodsForUnmigratedUsers() {
        when(configurationService.getEnvironment()).thenReturn("test");
        mockPhoneNumberIndexScan(0, 0);

        List<Map<String, AttributeValue>> credentialItems =
                List.of(
                        createUserWithAuthApp(1, false, false), // No auth app
                        createUserWithAuthApp(2, true, true), // Has verified auth app
                        createUserWithAuthApp(3, true, false), // Auth app enabled but not verified
                        createUserWithAuthApp(4, false, false) // No auth app
                        );

        mockCredentialsScan(credentialItems, credentialItems.size());

        List<Map<String, AttributeValue>> profileItems =
                List.of(
                        createProfileWithMigrationStatus(1, false, false), // Not migrated, no SMS
                        createProfileWithMigrationStatus(
                                2, false, false), // Not migrated, no SMS, but has auth app
                        createProfileWithMigrationStatus(3, false, true), // Not migrated, has SMS
                        createProfileWithMigrationStatus(4, false, true) // Not migrated, has SMS
                        );

        mockProfileBatchGetItem(createKeysFromCredentials(credentialItems), profileItems);

        var handler = new MFAMethodAnalysisHandler(configurationService, client);
        String result = handler.handleRequest("", mock(Context.class));

        // Only user 1 has no MFA methods (no auth app and no SMS)
        // User 2 has verified auth app, User 3 and 4 have SMS
        assertTrue(result.contains("countOfAccountsWithoutAnyMfaMethods=1"));
        assertTrue(result.contains("countOfUsersWithMfaMethodsMigrated=0"));
        assertTrue(result.contains("countOfUsersWithoutMfaMethodsMigrated=4"));
    }

    private Map<String, AttributeValue> createUserWithAuthApp(
            int userIndex, boolean enabled, boolean verified) {
        Map<String, AttributeValue> user = new HashMap<>();
        user.put("Email", AttributeValue.builder().s(getTestEmail(userIndex)).build());

        if (enabled || verified) {
            Map<String, AttributeValue> mfaMethod = new HashMap<>();
            mfaMethod.put("Enabled", AttributeValue.builder().n(enabled ? "1" : "0").build());
            mfaMethod.put(
                    "MethodVerified", AttributeValue.builder().n(verified ? "1" : "0").build());
            user.put(
                    "MfaMethods",
                    AttributeValue.builder()
                            .l(AttributeValue.builder().m(mfaMethod).build())
                            .build());
        }

        return user;
    }

    private Map<String, AttributeValue> createProfileWithMigrationStatus(
            int userIndex, boolean migrated, boolean phoneVerified) {
        Map<String, AttributeValue> profile = new HashMap<>();
        profile.put("Email", AttributeValue.builder().s(getTestEmail(userIndex)).build());
        profile.put("mfaMethodsMigrated", AttributeValue.builder().bool(migrated).build());
        profile.put(
                "PhoneNumberVerified",
                AttributeValue.builder().n(phoneVerified ? "1" : "0").build());
        return profile;
    }

    private String getTestEmail(int counter) {
        return "test-" + counter + "@example.com";
    }
}
