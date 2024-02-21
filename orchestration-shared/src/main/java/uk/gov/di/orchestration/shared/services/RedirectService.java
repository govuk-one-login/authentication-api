package uk.gov.di.orchestration.shared.services;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.helpers.ConstructUriHelper;

import java.util.Map;

import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class RedirectService {
    private static final Logger LOG = LogManager.getLogger(RedirectService.class);

    public static APIGatewayProxyResponseEvent redirectToFrontendErrorPage(
            String loginUri, String errorPagePath) {
        LOG.info("Redirecting to frontend error page: {}", errorPagePath);
        return generateApiGatewayProxyResponse(
                302,
                "",
                Map.of(
                        ResponseHeaders.LOCATION,
                        ConstructUriHelper.buildURI(loginUri, errorPagePath).toString()),
                null);
    }
}
