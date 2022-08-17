package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.ComparisonOperator;
import com.amazonaws.services.dynamodbv2.model.Condition;
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

import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoClient;

public class AccountVerifierLambda implements RequestHandler<Integer, Void> {

    private static final Logger LOG = LogManager.getLogger(AccountVerifierLambda.class);

    private final AmazonDynamoDB client;

    public AccountVerifierLambda() {
        client = createDynamoClient(new ConfigurationService());
    }

    public AccountVerifierLambda(AmazonDynamoDB client) {
        this.client = client;
    }

    @Override
    public Void handleRequest(Integer input, Context context) {

        var result =
                client.scan(
                        "sandpit-user-profile",
                        Map.of(
                                "PhoneNumberVerified",
                                new Condition()
                                        .withComparisonOperator(ComparisonOperator.EQ)
                                        .withAttributeValueList(new AttributeValue().withN("1")),
                                "accountVerified",
                                new Condition().withComparisonOperator(ComparisonOperator.NULL)));

        LOG.info("Found {} matching records", result.getItems().size());

        TransactWriteItemsRequest updateRequest = new TransactWriteItemsRequest();
        List<TransactWriteItem> updates = new ArrayList<>();
        if (result.getItems().isEmpty()) {
            LOG.info("No items found to update");
            return null;
        }
        result.getItems()
                .forEach(
                        itemMap -> {
                            updates.add(
                                    new TransactWriteItem()
                                            .withUpdate(
                                                    new Update()
                                                            .withTableName("sandpit-user-profile")
                                                            .withKey(
                                                                    Map.of(
                                                                            "Email",
                                                                            itemMap.get("Email")))
                                                            .withUpdateExpression(
                                                                    "SET accountVerified = :accountVerified")
                                                            .withExpressionAttributeValues(
                                                                    Map.of(
                                                                            ":accountVerified",
                                                                            new AttributeValue()
                                                                                    .withN("1")))));
                        });

        updateRequest.withTransactItems(updates);
        var updateResult = client.transactWriteItems(updateRequest);

        LOG.info("Update status code = {}", updateResult.getSdkHttpMetadata().getHttpStatusCode());
        return null;
    }
}
