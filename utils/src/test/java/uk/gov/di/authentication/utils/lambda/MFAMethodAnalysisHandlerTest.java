package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MFAMethodAnalysisHandlerTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoDbClient client = mock(DynamoDbClient.class);

    private final MFAMethodAnalysisHandler handler =
            new MFAMethodAnalysisHandler(configurationService, client);

    @Test
    void shouldFindTheNumberOfMatches() {
        when(configurationService.getEnvironment()).thenReturn("test");

        Map<String, AttributeValue> item = new HashMap<>();
        item.put("Email", AttributeValue.builder().s("test@example.com").build());

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

        Map<String, AttributeValue> keyToGet = new HashMap<>();
        keyToGet.put(
                UserProfile.ATTRIBUTE_EMAIL,
                AttributeValue.builder().s("test@example.com").build());
        when(client.getItem(
                        GetItemRequest.builder()
                                .tableName("test-user-profile")
                                .key(keyToGet)
                                .build()))
                .thenReturn(GetItemResponse.builder().item(item).build());

        assertEquals(1, handler.handleRequest("", mock(Context.class)));
    }
}
