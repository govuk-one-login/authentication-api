package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.text.MessageFormat.format;
import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoClient;

public class MFAMethodAnalysisHandler implements RequestHandler<String, Long> {

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
    public Long handleRequest(String input, Context context) {
        Map<String, String> expressionAttributeNames = new HashMap<>();
        Map<String, AttributeValue> lastKey = null;
        expressionAttributeNames.put("#mfa_methods", UserCredentials.ATTRIBUTE_MFA_METHODS);

        long matches = 0;
        long recordsProcessed = 0;

        String userCredentialsTableName =
                format("{0}-user-credentials", configurationService.getEnvironment());
        String userProfileTableName =
                format("{0}-user-profile", configurationService.getEnvironment());

        do {
            ScanRequest scanRequest =
                    ScanRequest.builder()
                            .tableName(userCredentialsTableName)
                            .filterExpression("attribute_exists(#mfa_methods)")
                            .expressionAttributeNames(expressionAttributeNames)
                            .exclusiveStartKey(lastKey)
                            .build();

            ScanResponse scanResponse = client.scan(scanRequest);

            List<String> emailsToGet = new ArrayList<>();
            for (Map<String, AttributeValue> userCredentialsItem : scanResponse.items()) {
                recordsProcessed++;
                if (recordsProcessed % 100000 == 0) {
                    LOG.info("Processed {} user credentials records", recordsProcessed);
                }
                String email = userCredentialsItem.get(UserCredentials.ATTRIBUTE_EMAIL).s();
                emailsToGet.add(email);

                if (emailsToGet.size() >= 100) {
                    matches += batchGetUserProfiles(emailsToGet, userProfileTableName);
                    emailsToGet.clear();
                }
            }

            if (!emailsToGet.isEmpty()) {
                matches += batchGetUserProfiles(emailsToGet, userProfileTableName);
            }

            lastKey = scanResponse.lastEvaluatedKey();
        } while (lastKey != null && !lastKey.isEmpty());

        LOG.info("Found {} credentials/profile matches with AUTH_APP", matches);

        return matches;
    }

    private long batchGetUserProfiles(List<String> emails, String userProfileTableName) {
        if (emails.isEmpty()) {
            return 0;
        }

        Map<String, KeysAndAttributes> requestItems = new HashMap<>();
        List<Map<String, AttributeValue>> keys = new ArrayList<>();
        for (String email : emails) {
            Map<String, AttributeValue> key = new HashMap<>();
            key.put(UserProfile.ATTRIBUTE_EMAIL, AttributeValue.builder().s(email).build());
            keys.add(key);
        }
        requestItems.put(userProfileTableName, KeysAndAttributes.builder().keys(keys).build());

        BatchGetItemRequest batchGetItemRequest =
                BatchGetItemRequest.builder().requestItems(requestItems).build();

        BatchGetItemResponse batchGetItemResponse = client.batchGetItem(batchGetItemRequest);
        Map<String, List<Map<String, AttributeValue>>> results = batchGetItemResponse.responses();

        if (results.containsKey(userProfileTableName)) {
            return results.get(userProfileTableName).size();
        }
        return 0;
    }
}
