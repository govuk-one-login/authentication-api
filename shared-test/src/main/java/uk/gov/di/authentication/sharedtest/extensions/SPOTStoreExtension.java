package uk.gov.di.authentication.sharedtest.extensions;

import com.amazonaws.services.dynamodbv2.model.AttributeDefinition;
import com.amazonaws.services.dynamodbv2.model.BillingMode;
import com.amazonaws.services.dynamodbv2.model.CreateTableRequest;
import com.amazonaws.services.dynamodbv2.model.KeySchemaElement;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import uk.gov.di.authentication.shared.services.DynamoSpotService;

import java.util.Optional;

import static com.amazonaws.services.dynamodbv2.model.KeyType.HASH;
import static com.amazonaws.services.dynamodbv2.model.ScalarAttributeType.S;

public class SPOTStoreExtension extends DynamoExtension implements AfterEachCallback {

    public static final String SUBJECT_ID_FIELD = "SubjectID";
    public static final String SPOT_TABLE = "local-spot-credential";

    private DynamoSpotService dynamoService;

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);
        dynamoService =
                new DynamoSpotService(REGION, ENVIRONMENT, Optional.of(DYNAMO_ENDPOINT), 300);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, SPOT_TABLE, SUBJECT_ID_FIELD);
    }

    @Override
    protected void createTables() {
        if (!tableExists(SPOT_TABLE)) {
            createUserProfileTable(SPOT_TABLE);
        }
    }

    public void addCredential(String subjectID, String serializedCredential) {
        dynamoService.addSpotResponse(subjectID, serializedCredential);
    }

    private void createUserProfileTable(String tableName) {
        CreateTableRequest request =
                new CreateTableRequest()
                        .withTableName(tableName)
                        .withKeySchema(new KeySchemaElement(SUBJECT_ID_FIELD, HASH))
                        .withBillingMode(BillingMode.PAY_PER_REQUEST)
                        .withAttributeDefinitions(new AttributeDefinition(SUBJECT_ID_FIELD, S));
        dynamoDB.createTable(request);
    }
}
