package uk.gov.di.accountmanagement.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.accountmanagement.entity.IADCircuitBreakerItem;

import java.time.Clock;

import static uk.gov.di.accountmanagement.entity.IADCircuitBreakerItem.PARTITION_KEY;

public class IADCircuitBreakerService {

    private static final Logger LOG = LogManager.getLogger(IADCircuitBreakerService.class);

    private final DynamoDbTable<IADCircuitBreakerItem> dynamoTable;
    private final Clock clock;

    public IADCircuitBreakerService(String tableName) {
        var client = DynamoDbClient.create();
        var enhancedClient = DynamoDbEnhancedClient.builder().dynamoDbClient(client).build();
        this.dynamoTable =
                enhancedClient.table(tableName, TableSchema.fromBean(IADCircuitBreakerItem.class));
        this.clock = Clock.systemUTC();
    }

    public IADCircuitBreakerService(DynamoDbTable<IADCircuitBreakerItem> dynamoTable, Clock clock) {
        this.dynamoTable = dynamoTable;
        this.clock = clock;
    }

    public boolean isCircuitBreakerActive() {
        LOG.info("Checking IAD circuit breaker status");

        var queryRequest =
                QueryEnhancedRequest.builder()
                        .queryConditional(
                                QueryConditional.keyEqualTo(
                                        Key.builder().partitionValue(PARTITION_KEY).build()))
                        .scanIndexForward(false)
                        .limit(1)
                        .consistentRead(true)
                        .build();

        var active =
                dynamoTable.query(queryRequest).stream()
                        .flatMap(page -> page.items().stream())
                        .findFirst()
                        .map(IADCircuitBreakerItem::isEnabled)
                        .orElse(false);

        LOG.info("IAD circuit breaker status: active={}", active);
        return active;
    }
}
