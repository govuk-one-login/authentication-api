package uk.gov.di.accountmanagement.helpers;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.ScanRequest;
import com.amazonaws.services.dynamodbv2.model.ScanResult;
import com.nimbusds.oauth2.sdk.id.Subject;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Map;
import java.util.Optional;

public class DynamoHelper {
    private static final String REGION = System.getenv().getOrDefault("AWS_REGION", "eu-west-2");
    private static final String ENVIRONMENT = System.getenv().getOrDefault("ENVIRONMENT", "local");
    private static final String DYNAMO_ENDPOINT =
            System.getenv().getOrDefault("DYNAMO_ENDPOINT", "http://localhost:8000");
    private static final DynamoService DYNAMO_SERVICE =
            new DynamoService(REGION, ENVIRONMENT, Optional.of(DYNAMO_ENDPOINT));

    public static void signUp(String email, String password) {
        signUp(email, password, new Subject());
    }

    public static void signUp(String email, String password, Subject subject) {
        TermsAndConditions termsAndConditions =
                new TermsAndConditions("1.0", LocalDateTime.now(ZoneId.of("UTC")).toString());
        DYNAMO_SERVICE.signUp(email, password, subject, termsAndConditions);
    }

    public static void flushData() {
        AmazonDynamoDB dynamoDB =
                AmazonDynamoDBClientBuilder.standard()
                        .withEndpointConfiguration(
                                new AwsClientBuilder.EndpointConfiguration(DYNAMO_ENDPOINT, REGION))
                        .build();

        clearDynamoTable(dynamoDB, "local-user-credentials", "Email");
        clearDynamoTable(dynamoDB, "local-user-profile", "Email");
        clearDynamoTable(dynamoDB, "local-client-registry", "ClientID");
    }

    private static void clearDynamoTable(AmazonDynamoDB dynamoDB, String tableName, String key) {
        ScanRequest scanRequest = new ScanRequest().withTableName(tableName);
        ScanResult result = dynamoDB.scan(scanRequest);

        for (Map<String, AttributeValue> item : result.getItems()) {
            dynamoDB.deleteItem(tableName, Map.of(key, item.get(key)));
        }
    }
}
