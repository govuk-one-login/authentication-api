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
import java.time.Duration;
import java.net.http.HttpResponse;

import static java.lang.String.format;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;

public class AccountInterventionsService {

    private static final Logger LOG = LogManager.getLogger(AccountInterventionsService.class);
    private final Json objectMapper = SerializationService.getInstance();

    private static HttpClient httpClient;

    private ConfigurationService configurationService = new ConfigurationService();

    public AccountInterventionsService() {
        httpClient = HttpClient.newHttpClient();
        configurationService = new ConfigurationService();
    }

    public AccountInterventionsService(ConfigurationService configService) {
        configurationService = configService;
        httpClient =
                HttpClient.newBuilder()
                        .connectTimeout(
                                Duration.ofMillis(
                                        configurationService
                                                .getAccountInterventionServiceCallTimeout()))
                        .build();
    }

    public AccountInterventionsService(HttpClient client, ConfigurationService configService) {
        httpClient = client;
        configurationService = configService;
    }

    public AccountInterventionsInboundResponse sendAccountInterventionsOutboundRequest(
            String internalPairwiseId) throws UnsuccessfulAccountInterventionsResponseException {
        try {
            LOG.info("Sending account interventions outbound request");
            var response = sendAccountInterventionsRequest(internalPairwiseId);
            if (response.statusCode() < 200 || response.statusCode() > 299) {
                throw new UnsuccessfulAccountInterventionsResponseException(
                        format(
                                "Error %s when attempting to call Account Interventions outbound endpoint: %s",
                                response.statusCode(), response.body()),
                        response.statusCode());
            }
            LOG.info("Received successful account interventions outbound response");
            return parseResponse(response);
        } catch (IOException e) {
            throw new UnsuccessfulAccountInterventionsResponseException(
                    "Error when attempting to call Account Interventions outbound endpoint", e);
        } catch (Json.JsonException | JsonParseException e) {
            throw new UnsuccessfulAccountInterventionsResponseException(
                    "Error parsing HTTP response", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new UnsuccessfulAccountInterventionsResponseException(
                    "Interrupted exception when attempting to call Account Interventions outbound endpoint",
                    e);
        }
    }

    private HttpResponse sendAccountInterventionsRequest(String internalPairwiseId)
            throws IOException, InterruptedException {
        var accountInterventionsEndpoint =
                configurationService.getAccountInterventionServiceURI().toString();
        var accountInterventionsURI =
                buildURI(accountInterventionsEndpoint, "/v1/ais/" + internalPairwiseId);
        var request = HttpRequest.newBuilder(accountInterventionsURI).build();
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private AccountInterventionsInboundResponse parseResponse(HttpResponse response)
            throws Json.JsonException, JsonParseException {
        return objectMapper.readValue(
                response.body().toString(), AccountInterventionsInboundResponse.class, true);
    }
}
