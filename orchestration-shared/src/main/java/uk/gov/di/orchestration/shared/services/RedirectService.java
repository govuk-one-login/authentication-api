package uk.gov.di.orchestration.shared.services;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.exceptions.NoSessionException;

import java.net.URI;
import java.util.Map;

import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class RedirectService {
    private static final Logger LOG = LogManager.getLogger(RedirectService.class);

    public static APIGatewayProxyResponseEvent redirectToFrontendErrorPage(
            URI errorPageUri, Throwable error) {
        var errorPageUriStr = errorPageUri.toString();
        LOG.atError()
                .withThrowable(error)
                .log("Redirecting to frontend error page: {}", errorPageUriStr);
        return generateApiGatewayProxyResponse(
                302, "", Map.of(ResponseHeaders.LOCATION, errorPageUriStr), null);
    }

    public static APIGatewayProxyResponseEvent redirectToFrontendErrorPageForNoSessionCookies(
            URI errorPageUri, NoSessionException error) {
        var errorPageUriStr = errorPageUri.toString();
        LOG.atWarn()
                .withThrowable(error)
                .log(
                        "Redirecting to frontend error page for no session cookies: {}",
                        errorPageUriStr);
        return generateApiGatewayProxyResponse(
                302, "", Map.of(ResponseHeaders.LOCATION, errorPageUriStr), null);
    }
}
