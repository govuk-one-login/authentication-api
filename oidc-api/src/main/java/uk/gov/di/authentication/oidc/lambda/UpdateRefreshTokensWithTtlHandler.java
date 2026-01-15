package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.lambda.LambdaTimer;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.OrchRefreshTokenService;

import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

public class UpdateRefreshTokensWithTtlHandler implements RequestHandler<Object, String> {

    private static final Logger LOG = LogManager.getLogger(UpdateRefreshTokensWithTtlHandler.class);
    private static final int DEFAULT_READ_WRITE_BATCH_SIZE = 100;
    public static final int LOG_INTERVAL = 500;

    private final OrchRefreshTokenService orchRefreshTokenService;

    public UpdateRefreshTokensWithTtlHandler() {
        this(new OrchRefreshTokenService(ConfigurationService.getInstance()));
    }

    public UpdateRefreshTokensWithTtlHandler(OrchRefreshTokenService orchRefreshTokenService) {
        this.orchRefreshTokenService = orchRefreshTokenService;
    }

    @Override
    public String handleRequest(Object input, Context context) {
        var config = parseInput(input);
        var readWriteBatchSize =
                config.getOrDefault("readWriteBatchSize", DEFAULT_READ_WRITE_BATCH_SIZE);

        var timer = new LambdaTimer(context);

        var updated = new AtomicInteger(0);
        LOG.info(
                "Starting update of refresh tokens without TTL (readWriteBatchSize={})",
                readWriteBatchSize);
        orchRefreshTokenService.processRefreshTokensWithoutTtlSequentially(
                timer,
                readWriteBatchSize,
                batch -> {
                    orchRefreshTokenService.updateRefreshTokenBatchTtlToNow(batch);
                    int currentCount = updated.addAndGet(batch.size());
                    if (currentCount % LOG_INTERVAL == 0) {
                        LOG.info("Updated {} tokens", currentCount);
                    }
                });

        LOG.info("Updated {} refresh tokens with current TTL", updated.get());
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
