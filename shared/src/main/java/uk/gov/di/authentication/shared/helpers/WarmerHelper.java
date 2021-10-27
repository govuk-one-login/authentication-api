package uk.gov.di.authentication.shared.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Optional;

import static java.lang.Thread.sleep;

public class WarmerHelper {
    private static final ConfigurationService configurationService =
            ConfigurationService.getInstance();
    private static final Logger LOGGER = LoggerFactory.getLogger(WarmerHelper.class);

    public static final String WARMUP_HEADER = "__WARMUP_REQUEST__";

    public static Optional<APIGatewayProxyResponseEvent> isWarming(
            APIGatewayProxyRequestEvent input) {
        if (input.getHeaders() != null && input.getHeaders().containsKey(WARMUP_HEADER)) {
            try {
                LOGGER.info("Warmup Request Received {}", input.getHeaders().get(WARMUP_HEADER));
                sleep(configurationService.getWarmupDelayMillis());
                LOGGER.info(
                        "Instance warmed for request {}", input.getHeaders().get(WARMUP_HEADER));
                return Optional.of(new APIGatewayProxyResponseEvent().withStatusCode(200));
            } catch (InterruptedException e) {
                LOGGER.error("Sleep was interrupted", e);
                throw new RuntimeException("Sleep was interrupted", e);
            }
        }
        return Optional.empty();
    }
}
