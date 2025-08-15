package uk.gov.di.orchestration.sharedtest.extensions;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import uk.gov.di.orchestration.shared.entity.AuthCodeExchangeData;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.OrchAuthCodeService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.sharedtest.basetest.DynamoTestConfiguration;

import java.time.Clock;
import java.util.Optional;

public class OrchAuthCodeExtension extends DynamoExtension implements AfterEachCallback {

    public static final String TABLE_NAME = "local-Orch-Auth-Code";
    public static final String ORCH_AUTH_CODE_ID_FIELD = "AuthCode";
    private OrchAuthCodeService orchAuthCodeService;
    private final ConfigurationService configurationService;
    private final Json objectMapper;

    public OrchAuthCodeExtension() {
        createInstance();
        this.configurationService =
                new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT);

        this.objectMapper = SerializationService.getInstance();

        orchAuthCodeService = new OrchAuthCodeService(configurationService);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);

        orchAuthCodeService = new OrchAuthCodeService(configurationService);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, TABLE_NAME, ORCH_AUTH_CODE_ID_FIELD);
    }

    @Override
    protected void createTables() {
        if (!tableExists(TABLE_NAME)) {
            createOrchAuthCodeTable();
        }
    }

    private void createOrchAuthCodeTable() {
        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(TABLE_NAME)
                        .keySchema(
                                KeySchemaElement.builder()
                                        .keyType(KeyType.HASH)
                                        .attributeName(ORCH_AUTH_CODE_ID_FIELD)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(ORCH_AUTH_CODE_ID_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build())
                        .build();
        dynamoDB.createTable(request);
    }

    public AuthorizationCode generateAndSaveAuthorisationCode(
            String clientId,
            String clientSessionId,
            String email,
            Long authTime,
            String internalPairwiseSubjectId) {
        return orchAuthCodeService.generateAndSaveAuthorisationCode(
                clientId, clientSessionId, email, authTime, internalPairwiseSubjectId);
    }

    public Optional<AuthCodeExchangeData> getExchangeDataForCode(String code) {
        return orchAuthCodeService.getExchangeDataForCode(code);
    }

    public void setClock(Clock clock) {
        orchAuthCodeService = new OrchAuthCodeService(configurationService, clock, objectMapper);
    }
}
