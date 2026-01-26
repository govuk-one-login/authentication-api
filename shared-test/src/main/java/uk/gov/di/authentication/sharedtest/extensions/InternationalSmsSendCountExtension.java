package uk.gov.di.authentication.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.InternationalSmsSendLimitService;
import uk.gov.di.authentication.sharedtest.basetest.DynamoTestConfiguration;

import java.util.ArrayList;
import java.util.Map;
import java.util.Optional;

public class InternationalSmsSendCountExtension extends DynamoExtension
        implements AfterEachCallback {

    public static final String PHONE_NUMBER_FIELD = "PhoneNumber";
    public static final String INTERNATIONAL_SMS_SEND_COUNT_TABLE =
            "local-international-sms-send-count";

    private final InternationalSmsSendLimitService internationalSmsSendLimitService;
    private final ConfigurationService configuration;

    public InternationalSmsSendCountExtension(int sendLimit) {
        createInstance();
        this.configuration =
                new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT) {
                    @Override
                    public int getInternationalSmsNumberSendLimit() {
                        return sendLimit;
                    }
                };
        internationalSmsSendLimitService = new InternationalSmsSendLimitService(configuration);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(
                dynamoDB, INTERNATIONAL_SMS_SEND_COUNT_TABLE, PHONE_NUMBER_FIELD, Optional.empty());
    }

    @Override
    protected void createTables() {
        if (!tableExists(INTERNATIONAL_SMS_SEND_COUNT_TABLE)) {
            createInternationalSmsSendCountTable();
        }
    }

    public boolean hasReachedInternationalSmsLimit(String phoneNumber) {
        return internationalSmsSendLimitService.hasReachedInternationalSmsLimit(phoneNumber);
    }

    public void recordSmsSent(String phoneNumber) {
        internationalSmsSendLimitService.recordSmsSent(phoneNumber);
    }

    public boolean hasRecordForPhoneNumber(String phoneNumber) {
        var getItemRequest =
                GetItemRequest.builder()
                        .tableName(INTERNATIONAL_SMS_SEND_COUNT_TABLE)
                        .key(
                                Map.of(
                                        PHONE_NUMBER_FIELD,
                                        AttributeValue.builder().s(phoneNumber).build()))
                        .build();

        return dynamoDB.getItem(getItemRequest).hasItem();
    }

    private void createInternationalSmsSendCountTable() {
        ArrayList<AttributeDefinition> attributeDefinitions = new ArrayList<>();
        attributeDefinitions.add(
                AttributeDefinition.builder()
                        .attributeName(PHONE_NUMBER_FIELD)
                        .attributeType("S")
                        .build());

        ArrayList<KeySchemaElement> tableKeySchema = new ArrayList<>();
        tableKeySchema.add(
                KeySchemaElement.builder()
                        .attributeName(PHONE_NUMBER_FIELD)
                        .keyType(KeyType.HASH)
                        .build());

        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(INTERNATIONAL_SMS_SEND_COUNT_TABLE)
                        .attributeDefinitions(attributeDefinitions)
                        .keySchema(tableKeySchema)
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .build();

        dynamoDB.createTable(request);
    }
}
