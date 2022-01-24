package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SNSEvent;
import uk.gov.di.authentication.shared.services.ConfigurationService;

public class SPOTResponseHandler implements RequestHandler<SNSEvent, Void> {

    public SPOTResponseHandler() {
        this(ConfigurationService.getInstance());
    }

    public SPOTResponseHandler(ConfigurationService configurationService) {}

    @Override
    public Void handleRequest(SNSEvent event, Context context) {
        return null;
    }
}
