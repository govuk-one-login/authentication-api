package uk.gov.di.authentication.shared.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Optional;

import static java.lang.Thread.sleep;

public class WarmerHelper {
    private static final ConfigurationService configurationService = new ConfigurationService();

    public static Optional<APIGatewayProxyResponseEvent> isWarming(APIGatewayProxyRequestEvent input) {
        if (input.getHttpMethod() == null) {
            try {
                sleep(configurationService.getWarmupDelayMillis());
                return Optional.of(new APIGatewayProxyResponseEvent().withBody("I'm warm").withStatusCode(200));
            } catch (InterruptedException e) {
                throw new RuntimeException("Sleep was interrupted");
            }
        }
        return Optional.empty();
    }
}
