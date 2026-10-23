package uk.gov.di.accountmanagement.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryEnhancedRequest;
import uk.gov.di.accountmanagement.entity.IADCircuitBreakerItem;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;

import static uk.gov.di.accountmanagement.entity.IADCircuitBreakerItem.PARTITION_KEY;
import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoEnhancedClient;

public class IADCircuitBreakerService {

    private static final Logger LOG = LogManager.getLogger(IADCircuitBreakerService.class);

    private final DynamoDbTable<IADCircuitBreakerItem> dynamoTable;
    private final Clock clock;
    private final Json serialisationService;

    public IADCircuitBreakerService(String tableName) {
        var enhancedClient = createDynamoEnhancedClient(ConfigurationService.getInstance());
        this.dynamoTable =
                enhancedClient.table(tableName, TableSchema.fromBean(IADCircuitBreakerItem.class));
        this.clock = Clock.systemUTC();
        this.serialisationService = SerializationService.getInstance();
    }

    public IADCircuitBreakerService(DynamoDbTable<IADCircuitBreakerItem> dynamoTable, Clock clock) {
        this.dynamoTable = dynamoTable;
        this.clock = clock;
        this.serialisationService = SerializationService.getInstance();
    }

    IADCircuitBreakerService(
            DynamoDbTable<IADCircuitBreakerItem> dynamoTable,
            Clock clock,
            Json serialisationService) {
        this.dynamoTable = dynamoTable;
        this.clock = clock;
        this.serialisationService = serialisationService;
    }

    public boolean isCircuitBreakerTripped() {
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

        var tripped =
                dynamoTable.query(queryRequest).stream()
                        .flatMap(page -> page.items().stream())
                        .findFirst()
                        .map(item -> !item.isEnabled())
                        .orElse(false);

        LOG.info("IAD circuit breaker status: tripped={}", tripped);
        return tripped;
    }

    public void tripCircuitBreaker(String guardrailType, String publicSubjectId) {
        LOG.warn(
                "Tripping IAD circuit breaker. guardrailType={}, publicSubjectId={}",
                guardrailType,
                publicSubjectId);

        var now = Instant.now(clock).toEpochMilli();
        String metadataJson = null;
        try {
            metadataJson =
                    serialisationService.writeValueAsStringCamelCase(
                            Map.of(
                                    "guardrailType", guardrailType,
                                    "publicSubjectId", publicSubjectId));
        } catch (Json.JsonException e) {
            LOG.warn(
                    "Failed to serialise circuit breaker metadata, writing item without metadata to ensure circuit breaker tripped",
                    e);
        }

        var item = new IADCircuitBreakerItem();
        item.setPk(PARTITION_KEY);
        item.setDatetime(now);
        // NOTE: enabled=false trips the breaker; enabled=true would mean healthy/continue
        // processing.
        item.setEnabled(false);
        item.setMetadataJson(metadataJson);

        dynamoTable.putItem(item);

        LOG.info("Successfully wrote IAD circuit breaker item. datetime={}", now);
    }
}
