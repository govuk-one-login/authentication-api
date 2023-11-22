package uk.gov.di.authentication.oidc.services;

import com.google.gson.Gson;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.entity.AccountInterventionResponse;
import uk.gov.di.authentication.oidc.entity.AccountInterventionStatus;
import uk.gov.di.authentication.oidc.exceptions.AccountInterventionException;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class AccountInterventionService {

    private static final Logger LOGGER = LogManager.getLogger(AccountInterventionService.class);
    private final boolean accountInterventionsEnabled;
    private final HttpClient httpClient;
    private final URI accountInterventionServiceURI;

    public AccountInterventionService(ConfigurationService configService, HttpClient httpClient) {
        this.accountInterventionsEnabled = configService.isAccountInterventionServiceEnabled();
        this.accountInterventionServiceURI = configService.getAccountInterventionServiceURI();
        this.httpClient = httpClient;
    }

    public AccountInterventionStatus getAccountStatus(String internalPairwiseSubjectId)
            throws AccountInterventionException {
        try {
            if (accountInterventionsEnabled) {
                return retrieveAccountStatus(internalPairwiseSubjectId);
            }

            return new AccountInterventionStatus(false, false, false, false);

        } catch (IOException | URISyntaxException | InterruptedException e) {
            throw new AccountInterventionException(
                    "Unable to connect to Account Intervention Service", e);
        }
    }

    private AccountInterventionStatus retrieveAccountStatus(String internalPairwiseSubjectId)
            throws IOException, InterruptedException, URISyntaxException {

        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(accountInterventionServiceURI.resolve(internalPairwiseSubjectId))
                        .GET()
                        .build();

        HttpResponse<String> httpResponse =
                httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        String body = httpResponse.body();

        var response = new Gson().fromJson(body, AccountInterventionResponse.class);

        return response.state();
    }
}
