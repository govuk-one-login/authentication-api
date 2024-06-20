package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import uk.gov.di.authentication.entity.TICFCRIRequest;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class TicfCriHandler implements RequestHandler<TICFCRIRequest, Void> {

    private final HttpClient httpClient;
    private final ConfigurationService configurationService;

    private static final SerializationService serialisationService =
            SerializationService.getInstance();

    public TicfCriHandler(HttpClient httpClient, ConfigurationService configurationService) {
        this.httpClient = httpClient;
        this.configurationService = configurationService;
    }

    public TicfCriHandler() {
        this.configurationService = ConfigurationService.getInstance();
        this.httpClient = HttpClient.newHttpClient();
    }

    private static final org.apache.logging.log4j.Logger LOG =
            LogManager.getLogger(TicfCriHandler.class);

    @Override
    public Void handleRequest(TICFCRIRequest input, Context context) {
        LOG.debug("received request to TICF CRI Handler");
        try {
            sendRequest(input);
        } catch (InterruptedException | IOException e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    private void sendRequest(TICFCRIRequest ticfcriRequest)
            throws IOException, InterruptedException {
        var body = serialisationService.writeValueAsStringNoNulls(ticfcriRequest);
        var request =
                HttpRequest.newBuilder(configurationService.getTicfCriServiceURI())
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build();
        httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }
}
