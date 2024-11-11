package uk.gov.di.authentication.frontendapi.services;

import com.google.gson.JsonParseException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.AccountInterventionsInboundResponse;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountInterventionsResponseException;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;

import static uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountInterventionsResponseException.httpResponseCodeException;
import static uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountInterventionsResponseException.interruptedException;
import static uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountInterventionsResponseException.ioException;
import static uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountInterventionsResponseException.parseException;
import static uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountInterventionsResponseException.timeoutException;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;

public class AccountInterventionsService {

    private static final Logger LOG = LogManager.getLogger(AccountInterventionsService.class);
    private final Json objectMapper = SerializationService.getInstance();

    private static HttpClient httpClient;

    private ConfigurationService configurationService;

    public AccountInterventionsService() {
        httpClient = HttpClient.newHttpClient();
        configurationService = new ConfigurationService();
    }

    public AccountInterventionsService(ConfigurationService configService) {
        configurationService = configService;
        httpClient = HttpClient.newHttpClient();
    }

    public AccountInterventionsService(HttpClient client, ConfigurationService configService) {
        httpClient = client;
        configurationService = configService;
    }

    public AccountInterventionsInboundResponse sendAccountInterventionsOutboundRequest(
            String internalPairwiseId) throws UnsuccessfulAccountInterventionsResponseException {
        LOG.info("Sending account interventions outbound request");
        var response = sendAccountInterventionsRequest(internalPairwiseId);
        if (response.statusCode() < 200 || response.statusCode() > 299) {
            throw httpResponseCodeException(response.statusCode(), response.body());
        }
        LOG.info("Received successful account interventions outbound response");
        return parseResponse(response);
    }

    private HttpResponse sendAccountInterventionsRequest(String internalPairwiseId)
            throws UnsuccessfulAccountInterventionsResponseException {
        var accountInterventionsEndpoint =
                configurationService.getAccountInterventionServiceURI().toString();
        var accountInterventionsURI =
                buildURI(accountInterventionsEndpoint, "/v1/ais/" + internalPairwiseId);
        var request =
                HttpRequest.newBuilder(accountInterventionsURI)
                        .timeout(
                                Duration.ofMillis(
                                        configurationService
                                                .getAccountInterventionServiceCallTimeout()))
                        .build();
        try {
            if (configurationService.canLogInternalPairwiseId()) {
                LOG.info(
                        "Sending account interventions request with internalPairwiseId {}",
                        internalPairwiseId);
            }
            var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (configurationService.canLogInternalPairwiseId()) {
                LOG.info(
                        "Recieved account interventions response for internalPairwiseId {}",
                        internalPairwiseId);
            }
            return response;
        } catch (HttpTimeoutException e) {
            throw timeoutException(
                    configurationService.getAccountInterventionServiceCallTimeout(), e);
        } catch (IOException e) {
            throw ioException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw interruptedException(e);
        }
    }

    private AccountInterventionsInboundResponse parseResponse(HttpResponse response)
            throws UnsuccessfulAccountInterventionsResponseException {
        try {
            return objectMapper.readValue(
                    response.body().toString(), AccountInterventionsInboundResponse.class, true);
        } catch (Json.JsonException | JsonParseException e) {
            throw parseException(e);
        }
    }
}
