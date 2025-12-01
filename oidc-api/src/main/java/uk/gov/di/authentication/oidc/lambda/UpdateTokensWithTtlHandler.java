package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.OrchAccessTokenService;

import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

public class UpdateTokensWithTtlHandler implements RequestHandler<Object, String> {

    private static final Logger LOG = LogManager.getLogger(UpdateTokensWithTtlHandler.class);
    private static final int DEFAULT_READ_BATCH_SIZE = 1000;
    private static final int DEFAULT_WRITE_BATCH_SIZE = 1;
    public static final int DEFAULT_SEGMENTS = 1;
    public static final int DEFAULT_MAX_TOKENS = 1000;
    public static final int LOG_INTERVAL = 500;

    private final OrchAccessTokenService orchAccessTokenService;

    public UpdateTokensWithTtlHandler() {
        this.orchAccessTokenService =
                new OrchAccessTokenService(ConfigurationService.getInstance());
    }

    public UpdateTokensWithTtlHandler(OrchAccessTokenService orchAccessTokenService) {
        this.orchAccessTokenService = orchAccessTokenService;
    }

    @Override
    public String handleRequest(Object input, Context context) {
        var config = parseInput(input);
        var readBatchSize = config.getOrDefault("readBatchSize", DEFAULT_READ_BATCH_SIZE);
        var writeBatchSize = config.getOrDefault("writeBatchSize", DEFAULT_WRITE_BATCH_SIZE);
        var totalSegments = config.getOrDefault("totalSegments", DEFAULT_SEGMENTS);

        // because of parallel processing, tokens updated may exceed maxTokens slightly
        var maxTokens = config.getOrDefault("maxTokens", DEFAULT_MAX_TOKENS);

        LOG.info(
                "Starting update of access tokens without TTL (readBatch={}, writeBatch={}, segments={}, maxTokens={})",
                readBatchSize,
                writeBatchSize,
                totalSegments,
                maxTokens);

        var updated = new AtomicInteger(0);
        orchAccessTokenService.processAccessTokensWithoutTtlInBatches(
                readBatchSize,
                totalSegments,
                maxTokens,
                batch -> {
                    // Process the batch in sub-batches for writing
                    for (int i = 0; i < batch.size(); i += writeBatchSize) {
                        var writeBatch =
                                new ArrayList<>(
                                        batch.subList(
                                                i, Math.min(i + writeBatchSize, batch.size())));
                        orchAccessTokenService.updateAccessTokensTtlToNow(writeBatch);
                        int currentCount = updated.addAndGet(writeBatch.size());
                        if (currentCount % LOG_INTERVAL == 0) {
                            LOG.info("Updated {} tokens", currentCount);
                        }
                    }
                });

        LOG.info("Updated {} access tokens with current TTL", updated.get());
        return "Finished";
    }

    @SuppressWarnings("unchecked")
    private Map<String, Integer> parseInput(Object input) {
        if (input instanceof Map) {
            return (Map<String, Integer>) input;
        }
        return Map.of();
    }
}
