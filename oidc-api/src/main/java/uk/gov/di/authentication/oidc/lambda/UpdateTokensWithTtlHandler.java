package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.OrchAccessTokenService;

import java.util.concurrent.atomic.AtomicInteger;

public class UpdateTokensWithTtlHandler implements RequestHandler<Object, String> {

    private static final Logger LOG = LogManager.getLogger(UpdateTokensWithTtlHandler.class);
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
        LOG.info("Starting update of access tokens without TTL");

        var updated = new AtomicInteger(0);
        orchAccessTokenService.processAccessTokensWithoutTtlInBatches(
                100,
                batch -> {
                    batch.forEach(orchAccessTokenService::updateAccessTokenTtlToNow);
                    int currentCount = updated.addAndGet(batch.size());
                    LOG.info("Updated {} tokens", currentCount);
                });

        LOG.info("Updated {} access tokens with current TTL", updated.get());
        return "Finished";
    }
}
