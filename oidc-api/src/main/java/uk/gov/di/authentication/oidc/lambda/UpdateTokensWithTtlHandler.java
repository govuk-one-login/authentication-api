package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.OrchAccessTokenService;

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

        var tokensWithoutTtl = orchAccessTokenService.getAccessTokensWithoutTtl();
        LOG.info("Found {} tokens without TTL", tokensWithoutTtl.size());

        int updated = 0;
        for (var token : tokensWithoutTtl) {
            orchAccessTokenService.updateAccessTokenTtlToNow(token);
            updated++;
            if (updated % 100 == 0) {
                LOG.info("Updated {} tokens", updated);
            }
        }

        LOG.info("Updated {} access tokens with current TTL", updated);
        return "Finished";
    }
}
