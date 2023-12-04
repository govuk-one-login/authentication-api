package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.AccountInterventionResponse;
import uk.gov.di.orchestration.shared.entity.AccountInterventionStatus;
import uk.gov.di.orchestration.shared.exceptions.AccountInterventionException;
import uk.gov.di.orchestration.shared.serialization.Json;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class AccountInterventionService {

    private static final Logger LOGGER = LogManager.getLogger(AccountInterventionService.class);
    private final HttpClient httpClient;
    private final URI accountInterventionServiceURI;
    private final ConfigurationService configurationService;

    public AccountInterventionService(ConfigurationService configService, HttpClient httpClient) {
        this.configurationService = configService;
        this.accountInterventionServiceURI = configService.getAccountInterventionServiceURI();
        this.httpClient = httpClient;
    }

    public AccountInterventionStatus getAccountStatus(String internalPairwiseSubjectId)
            throws AccountInterventionException {
        try {
            return retrieveAccountStatus(internalPairwiseSubjectId);
        } catch (IOException | URISyntaxException | Json.JsonException e) {
            if (configurationService.isAccountInterventionServiceEnabled()) {
                throw new AccountInterventionException(
                        "Problem communicating with Account Intervention Service", e);
            } else {
                LOGGER.warn("Problem communicating with Account Intervention Service " + e);
                return noInterventionResponse();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AccountInterventionException(
                    "Problem communicating with Account Intervention Service", e);
        }
    }

    private AccountInterventionStatus retrieveAccountStatus(String internalPairwiseSubjectId)
            throws IOException, InterruptedException, URISyntaxException, Json.JsonException {

        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(accountInterventionServiceURI.resolve(internalPairwiseSubjectId))
                        .GET()
                        .build();

        HttpResponse<String> httpResponse =
                httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        String body = httpResponse.body();

        var response =
                SerializationService.getInstance()
                        .readValue(body, AccountInterventionResponse.class);

        return response.state();
    }

    private static AccountInterventionStatus noInterventionResponse() {
        return new AccountInterventionStatus(false, false, false, false);
    }
}
