package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.ScanRequest;
import com.amazonaws.services.dynamodbv2.model.ScanResult;
import com.amazonaws.services.dynamodbv2.model.TransactWriteItem;
import com.amazonaws.services.dynamodbv2.model.TransactWriteItemsRequest;
import com.amazonaws.services.dynamodbv2.model.Update;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static java.util.Objects.nonNull;
import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoClient;

public class AccountVerifierLambda implements RequestHandler<Integer, Void> {

    private static final Logger LOG = LogManager.getLogger(AccountVerifierLambda.class);
    public static final String EMAIL = "Email";
    public static final String ACCOUNT_VERIFIED = "accountVerified";
    public static final String PHONE_NUMBER_VERIFIED = "PhoneNumberVerified";
    public static final String TRUE_N = "1";

    private final AmazonDynamoDB client;
    private final ConfigurationService configurationService;

    public AccountVerifierLambda() {
        configurationService = ConfigurationService.getInstance();
        client = createDynamoClient(configurationService);
    }

    public AccountVerifierLambda(AmazonDynamoDB client, ConfigurationService configurationService) {
        this.client = client;
        this.configurationService = configurationService;
    }

    @Override
    public Void handleRequest(Integer input, Context context) {
        var batchSize = input.intValue();
        Map<String, AttributeValue> lastKeyEvaluated = null;

        List<TransactWriteItem> updates = new ArrayList<>();
        do {
            var result = getRecords(batchSize, lastKeyEvaluated);
            lastKeyEvaluated = result.getLastEvaluatedKey();
            LOG.info("Found {} matching records", result.getItems().size());

            result.getItems()
                    .forEach(
                            itemMap -> {
                                if (!itemMap.containsKey(ACCOUNT_VERIFIED)) {
                                    if (accountIsVerified(itemMap)) {
                                        updates.add(updateForItem(itemMap));
                                        if (updates.size() == 25) {
                                            submit(client, updates);
                                            updates.clear();
                                        }
                                    }
                                }
                            });
        } while (nonNull(lastKeyEvaluated));
        if (!updates.isEmpty()) submit(client, updates);

        return null;
    }

    private TransactWriteItem updateForItem(Map<String, AttributeValue> item) {
        return new TransactWriteItem()
                .withUpdate(
                        new Update()
                                .withTableName("sandpit-user-profile")
                                .withKey(
                                        Map.of(
                                                EMAIL,
                                                item.get(EMAIL)))
                                .withUpdateExpression(
                                        "SET accountVerified = :accountVerified")
                                .withExpressionAttributeValues(
                                        Map.of(
                                                ":accountVerified",
                                                new AttributeValue()
                                                        .withN(TRUE_N))));
    }

    private ScanResult getRecords(int batchSize, Map<String, AttributeValue> lastEvaluatedKey) {
        var request = new ScanRequest()
                .withTableName("sandpit-user-profile")
                .withConsistentRead(true)
                .withAttributesToGet(EMAIL, ACCOUNT_VERIFIED, PHONE_NUMBER_VERIFIED)
                .withLimit(batchSize)
                .withExclusiveStartKey(lastEvaluatedKey);

        return client.scan(request);
    }

    private boolean accountIsVerified(Map<String, AttributeValue> itemMap) {
        if (itemMap.get(PHONE_NUMBER_VERIFIED).getN().equals(TRUE_N)) return true;
        return hasVerifiedAuthenticationApp(itemMap.get(EMAIL).getS());
    }

    private boolean hasVerifiedAuthenticationApp(String email) {
        return false;
    }

    private void submit(AmazonDynamoDB client, List<TransactWriteItem> updates) {
        TransactWriteItemsRequest updateRequest = new TransactWriteItemsRequest();

        updateRequest.withTransactItems(updates);
        var updateResult = client.transactWriteItems(updateRequest);

        LOG.info("Update status code = {}", updateResult.getSdkHttpMetadata().getHttpStatusCode());
    }
}
