package uk.gov.di.orchestration.shared.services;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;

import java.net.URI;
import java.util.Map;

import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class RedirectService {
    private static final Logger LOG = LogManager.getLogger(RedirectService.class);

    public static APIGatewayProxyResponseEvent redirectToFrontendErrorPageWithWarnLog(
            URI errorPageUri, Throwable error) {
        var errorPageUriStr = errorPageUri.toString();
        LOG.atWarn()
                .withThrowable(error)
                .log("Redirecting to frontend error page: {}", errorPageUriStr);
        return redirectToFrontendErrorPage(errorPageUriStr);
    }

    public static APIGatewayProxyResponseEvent redirectToFrontendErrorPageWithErrorLog(
            URI errorPageUri, Throwable error) {
        var errorPageUriStr = errorPageUri.toString();
        LOG.atError()
                .withThrowable(error)
                .log("Redirecting to frontend error page: {}", errorPageUriStr);
        return redirectToFrontendErrorPage(errorPageUriStr);
    }

    public static APIGatewayProxyResponseEvent redirectToFrontendErrorPage(String errorPageUriStr) {
        return generateApiGatewayProxyResponse(
                302, "", Map.of(ResponseHeaders.LOCATION, errorPageUriStr), null);
    }

    public static APIGatewayProxyResponseEvent redirectToFrontendErrorPageForNoSession(
            URI errorPageUri, Exception error) {
        var errorPageUriStr = errorPageUri.toString();
        LOG.atWarn()
                .withThrowable(error)
                .log(
                        "Redirecting to frontend error page for no session: {}. Error: {}",
                        errorPageUriStr,
                        error.getMessage());
        return redirectToFrontendErrorPage(errorPageUriStr);
    }
}
