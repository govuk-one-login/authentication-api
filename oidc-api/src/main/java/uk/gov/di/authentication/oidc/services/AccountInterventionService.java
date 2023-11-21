package uk.gov.di.authentication.oidc.services;

import com.google.gson.Gson;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.entity.AccountInterventionResponse;
import uk.gov.di.authentication.oidc.entity.AccountInterventionStatus;
import uk.gov.di.authentication.oidc.exceptions.AccountInterventionException;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class AccountInterventionService {

    private static final Logger LOGGER = LogManager.getLogger(AccountInterventionService.class);
    private final boolean accountInterventionsAuditEnabled;
    private final boolean accountInterventionsEnabled;
    private final HttpClient httpClient;
    private final URI accountInterventionServiceURI;
    private final AuditService auditService;

    public AccountInterventionService(
            ConfigurationService configService, AuditService auditService, HttpClient httpClient) {
        this.accountInterventionsAuditEnabled =
                configService.isAccountInterventionServiceAuditEnabled();
        this.accountInterventionsEnabled = configService.isAccountInterventionServiceEnabled();
        this.accountInterventionServiceURI = configService.getAccountInterventionServiceURI();
        this.auditService = auditService;
        this.httpClient = httpClient;
    }

    public AccountInterventionStatus getAccountStatus(String internalSubjectId)
            throws AccountInterventionException {
        try {
            if (accountInterventionsEnabled) {
                return retrieveAccountStatus(internalSubjectId);
            }

            if (accountInterventionsAuditEnabled) {
                sendAuditEvent();
            }

            return new AccountInterventionStatus(false, false, false, false);

        } catch (IOException | URISyntaxException | InterruptedException e) {
            throw new AccountInterventionException(e);
        }
    }

    private AccountInterventionStatus retrieveAccountStatus(String internalSubjectId)
            throws IOException, InterruptedException, URISyntaxException {

        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(accountInterventionServiceURI.resolve(internalSubjectId))
                        .GET()
                        .build();

        HttpResponse<String> httpResponse =
                httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        String body = httpResponse.body();

        var response = new Gson().fromJson(body, AccountInterventionResponse.class);

        return response.state();
    }

    private void sendAuditEvent() {}
}
