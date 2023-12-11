package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.audit.AuditContext;
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

import static uk.gov.di.orchestration.shared.domain.AccountInterventionsAuditableEvent.AIS_RESPONSE_RECEIVED;

public class AccountInterventionService {

    private static final Logger LOGGER = LogManager.getLogger(AccountInterventionService.class);

    private final boolean accountInterventionsEnabled;
    private final boolean accountInterventionsAuditEnabled;
    private final HttpClient httpClient;
    private final URI accountInterventionServiceURI;
    private final AuditService auditService;

    public AccountInterventionService(
            ConfigurationService configService, HttpClient httpClient, AuditService auditService) {
        this.accountInterventionsEnabled = configService.isAccountInterventionServiceEnabled();
        this.accountInterventionsAuditEnabled =
                configService.isAccountInterventionServiceAuditEnabled();
        this.accountInterventionServiceURI = configService.getAccountInterventionServiceURI();
        this.httpClient = httpClient;
        this.auditService = auditService;
    }

    public AccountInterventionService(ConfigurationService configService) {
        this.accountInterventionsEnabled = configService.isAccountInterventionServiceEnabled();
        this.accountInterventionsAuditEnabled =
                configService.isAccountInterventionServiceAuditEnabled();
        this.accountInterventionServiceURI = configService.getAccountInterventionServiceURI();
        this.httpClient = HttpClient.newHttpClient();
        this.auditService = new AuditService(configService);
    }

    public AccountInterventionStatus getAccountStatus(String internalPairwiseSubjectId)
            throws AccountInterventionException {
        return getAccountStatus(internalPairwiseSubjectId, null);
    }

    public AccountInterventionStatus getAccountStatus(
            String internalPairwiseSubjectId, AuditContext auditContext)
            throws AccountInterventionException {

        if (accountInterventionsEnabled) {
            try {
                var status = retrieveAccountStatus(internalPairwiseSubjectId);
                if (accountInterventionsAuditEnabled) {
                    if (auditContext == null) {
                        throw new AccountInterventionException(
                                "Account intervention Audit enabled, but no AuditContext provided");
                    }
                    auditService.submitAuditEvent(AIS_RESPONSE_RECEIVED, auditContext);
                }
                return status;

            } catch (IOException | URISyntaxException | Json.JsonException e) {
                throw new AccountInterventionException(
                        "Problem communicating with Account Intervention Service", e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new AccountInterventionException(
                        "Problem communicating with Account Intervention Service", e);
            }
        }
        return noInterventionResponse();
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
