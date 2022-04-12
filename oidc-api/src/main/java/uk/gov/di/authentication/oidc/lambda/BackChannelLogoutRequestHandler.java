package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.services.ConfigurationService;

public class BackChannelLogoutRequestHandler implements RequestHandler<SQSEvent, Object> {

    private static final Logger LOG = LogManager.getLogger(BackChannelLogoutRequestHandler.class);
    private final ConfigurationService instance;

    public BackChannelLogoutRequestHandler() {
        this(ConfigurationService.getInstance());
    }

    public BackChannelLogoutRequestHandler(ConfigurationService configurationService) {
        this.instance = configurationService;
    }

    @Override
    public Object handleRequest(SQSEvent event, Context context) {

        event.getRecords()
                .forEach(
                        record ->
                                LOG.info(
                                        "Handling backchannel logout request with id: {}",
                                        record.getMessageId()));
        return null;
    }
}
