package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import uk.gov.di.authentication.entity.ExternalTICFCRIRequest;
import uk.gov.di.authentication.entity.InternalTICFCRIRequest;
import uk.gov.di.authentication.shared.helpers.HttpClientHelper;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.Map;

import static java.lang.String.format;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachTraceId;

public class TicfCriHandler implements RequestHandler<InternalTICFCRIRequest, Void> {

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
        this.httpClient = HttpClientHelper.newInstrumentedHttpClient();
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
    }

    private static final org.apache.logging.log4j.Logger LOG =
            LogManager.getLogger(TicfCriHandler.class);

    @Override
    public Void handleRequest(InternalTICFCRIRequest input, Context context) {
        attachTraceId();
        LOG.debug("received request to TICF CRI Handler");
        var environmentForMetrics = Map.entry("Environment", configurationService.getEnvironment());
        try {
            var response = sendRequest(input);
            var statusCode = response.statusCode();
            var logMessage =
                    format("Response received from TICF CRI Service with status %s", statusCode);
            LOG.log(statusCode >= 400 && statusCode < 500 ? Level.ERROR : Level.INFO, logMessage);
            cloudwatchMetricsService.incrementCounter(
                    "TicfCriResponseReceived",
                    Map.ofEntries(
                            environmentForMetrics,
                            Map.entry("StatusCode", String.valueOf(statusCode))));
        } catch (HttpTimeoutException e) {
            LOG.warn(
                    format(
                            "Request to TICF CRI timed out with timeout set to %d",
                            configurationService.getTicfCriServiceCallTimeout()),
                    e);
            sendMetricsForInterventionsError("TicfCriServiceTimeout");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOG.error(format("Error occurred in the TICF CRI Handler: %s", e.getMessage()), e);
            sendMetricsForInterventionsError("TicfCriServiceError");
        } catch (IOException e) {
            if (e.getCause() instanceof LinkageError) {
                // In rare cases we see a linkage error within the HTTP Client
                // which fails all future requests made by the lambda
                // As a temporary measure we crash the lambda to force a restart
                LOG.error("Linkage error making TICF request, exiting with fault");
                System.exit(1);
            }
            LOG.error(format("Error occurred in the TICF CRI Handler: %s", e.getMessage()), e);
            sendMetricsForInterventionsError("TicfCriServiceError");
        }
        return null;
    }

    private void sendMetricsForInterventionsError(String metric) {
        cloudwatchMetricsService.incrementCounter(
                metric, Map.of("Environment", configurationService.getEnvironment()));
    }

    private HttpResponse<String> sendRequest(InternalTICFCRIRequest internalTICFCRIRequest)
            throws IOException, InterruptedException {
        var externalRequest = ExternalTICFCRIRequest.fromInternalRequest(internalTICFCRIRequest);
        var body = serialisationService.writeValueAsStringNoNulls(externalRequest);
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
