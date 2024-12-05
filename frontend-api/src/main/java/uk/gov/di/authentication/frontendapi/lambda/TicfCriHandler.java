package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import uk.gov.di.authentication.entity.TICFCRIRequest;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.Collections;
import java.util.Map;

import static java.lang.String.format;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;

public class TicfCriHandler implements RequestHandler<TICFCRIRequest, Void> {

    private final HttpClient httpClient;
    private final ConfigurationService configurationService;
    private final CloudwatchMetricsService cloudwatchMetricsService;

    private static final SerializationService serialisationService =
            SerializationService.getInstance();

    public TicfCriHandler(
            HttpClient httpClient,
            ConfigurationService configurationService,
            CloudwatchMetricsService cloudwatchMetricsService) {
        this.httpClient = httpClient;
        this.configurationService = configurationService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
    }

    public TicfCriHandler() {
        this.configurationService = ConfigurationService.getInstance();
        this.httpClient = HttpClient.newHttpClient();
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
    }

    private static final org.apache.logging.log4j.Logger LOG =
            LogManager.getLogger(TicfCriHandler.class);

    @Override
    public Void handleRequest(TICFCRIRequest input, Context context) {
        LOG.debug("received request to TICF CRI Handler");
        try {
            var response = sendRequest(input);
            var statusCode = String.valueOf(response.statusCode());
            var logMessage =
                    format(
                            "Response received from TICF CRI Service with status %s and body %s",
                            statusCode, response.body());
            LOG.info(logMessage);
            cloudwatchMetricsService.incrementCounter(
                    "TicfCriResponseReceived", Map.ofEntries(Map.entry("StatusCode", statusCode)));
        } catch (HttpTimeoutException e) {
            var errorDescription =
                    format(
                            "Request to TICF CRI timed out with timeout set to %d",
                            configurationService.getTicfCriServiceCallTimeout());
            logAndSendMetricsForInterventionsError(
                    errorDescription, "TicfCriServiceTimeout", false);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            var errorDescription = format("Error occurred in the TICF CRI Handler: %s", e);
            logAndSendMetricsForInterventionsError(errorDescription, "TicfCriServiceError", true);
        } catch (IOException e) {
            var errorDescription = format("Error occurred in the TICF CRI Handler: %s", e);
            logAndSendMetricsForInterventionsError(errorDescription, "TicfCriServiceError", true);
        }
        return null;
    }

    private void logAndSendMetricsForInterventionsError(
            String errorDescription, String metric, Boolean raiseErrorLog) {
        if (Boolean.TRUE.equals(raiseErrorLog)) {
            LOG.error(errorDescription);
        } else {
            LOG.warn(errorDescription);
        }
        cloudwatchMetricsService.incrementCounter(metric, Collections.emptyMap());
    }

    private HttpResponse<String> sendRequest(TICFCRIRequest ticfcriRequest)
            throws IOException, InterruptedException {
        var body = serialisationService.writeValueAsStringNoNulls(ticfcriRequest);
        var timeoutInMilliseconds =
                Duration.ofMillis(configurationService.getTicfCriServiceCallTimeout());
        var request =
                HttpRequest.newBuilder(
                                buildURI(configurationService.getTicfCriServiceURI(), "/auth"))
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .timeout(timeoutInMilliseconds)
                        .build();
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }
}
