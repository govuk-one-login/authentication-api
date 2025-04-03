package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.HashMap;
import java.util.Map;

import static java.text.MessageFormat.format;
import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoClient;

public class MFAMethodAnalysisHandler implements RequestHandler<String, Integer> {

    private static final Logger LOG = LogManager.getLogger(MFAMethodAnalysisHandler.class);
    private final ConfigurationService configurationService;
    private final DynamoDbClient client;

    public MFAMethodAnalysisHandler(
            ConfigurationService configurationService, DynamoDbClient client) {
        this.configurationService = configurationService;
        this.client = client;
    }

    public MFAMethodAnalysisHandler() {
        this.configurationService = ConfigurationService.getInstance();
        client = createDynamoClient(configurationService);
    }

    @Override
    public Integer handleRequest(String input, Context context) {
        Map<String, String> expressionAttributeNames = new HashMap<>();
        Map<String, AttributeValue> lastKey;
        expressionAttributeNames.put("#mfa_methods", UserCredentials.ATTRIBUTE_MFA_METHODS);

        int matches = 0;
        do {
            ScanRequest scanRequest =
                    ScanRequest.builder()
                            .tableName(
                                    format(
                                            "{0}-user-credentials",
                                            configurationService.getEnvironment()))
                            .filterExpression("attribute_exists(#mfa_methods)")
                            .expressionAttributeNames(expressionAttributeNames)
                            .build();

            ScanResponse scanResponse = client.scan(scanRequest);

            for (Map<String, AttributeValue> userCredentialsItem : scanResponse.items()) {
                String email = userCredentialsItem.get(UserCredentials.ATTRIBUTE_EMAIL).s();

                Map<String, AttributeValue> keyToGet = new HashMap<>();
                keyToGet.put(
                        UserProfile.ATTRIBUTE_EMAIL, AttributeValue.builder().s(email).build());
                GetItemRequest getItemRequest =
                        GetItemRequest.builder()
                                .tableName(
                                        format(
                                                "{0}-user-profile",
                                                configurationService.getEnvironment()))
                                .key(keyToGet)
                                .build();

                GetItemResponse userProfileResponse = client.getItem(getItemRequest);
                Map<String, AttributeValue> userProfileItem = userProfileResponse.item();

                if (userProfileItem != null && !userProfileItem.isEmpty()) {
                    matches++;
                }
            }

            lastKey = scanResponse.lastEvaluatedKey();
        } while (lastKey != null && !lastKey.isEmpty());

        LOG.info("Found {} credentials/profile matches with AUTH_APP", matches);

        return matches;
    }
}
