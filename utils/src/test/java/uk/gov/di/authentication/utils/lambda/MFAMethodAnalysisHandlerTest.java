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
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MFAMethodAnalysisHandlerTest {

    public static final String TEST_EMAIL = "test@example.com";
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoDbClient client = mock(DynamoDbClient.class);

    private final MFAMethodAnalysisHandler handler =
            new MFAMethodAnalysisHandler(configurationService, client);

    @Test
    void shouldFindTheNumberOfMatches() {
        when(configurationService.getEnvironment()).thenReturn("test");

        Map<String, AttributeValue> item = new HashMap<>();
        item.put("Email", AttributeValue.builder().s(TEST_EMAIL).build());

        Map<String, String> expressionAttributeNames = new HashMap<>();
        expressionAttributeNames.put("#mfa_methods", UserCredentials.ATTRIBUTE_MFA_METHODS);
        when(client.scan(
                        ScanRequest.builder()
                                .tableName("test-user-credentials")
                                .filterExpression("attribute_exists(#mfa_methods)")
                                .expressionAttributeNames(expressionAttributeNames)
                                .build()))
                .thenReturn(
                        ScanResponse.builder()
                                .items(Collections.singletonList(item))
                                .count(1)
                                .scannedCount(1)
                                .build());

        Map<String, KeysAndAttributes> requestItems = new HashMap<>();

        List<Map<String, AttributeValue>> keys = new ArrayList<>();
        Map<String, AttributeValue> key = new HashMap<>();
        key.put(UserProfile.ATTRIBUTE_EMAIL, AttributeValue.builder().s(TEST_EMAIL).build());
        keys.add(key);
        requestItems.put("test-user-profile", KeysAndAttributes.builder().keys(keys).build());
        Map<String, List<Map<String, AttributeValue>>> responses = new HashMap<>();
        responses.put("test-user-profile", List.of(item));
        when(client.batchGetItem(BatchGetItemRequest.builder().requestItems(requestItems).build()))
                .thenReturn(BatchGetItemResponse.builder().responses(responses).build());

        assertEquals(1, handler.handleRequest("", mock(Context.class)));
    }
}
