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
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;

import static uk.gov.di.orchestration.shared.domain.AccountInterventionsAuditableEvent.AIS_RESPONSE_RECEIVED;

public class AccountInterventionService {

    private static final Logger LOG = LogManager.getLogger(AccountInterventionService.class);
    private final HttpClient httpClient;
    private final URI accountInterventionServiceURI;
    private final AuditService auditService;
    private final boolean accountInterventionsCallEnabled;
    private final boolean accountInterventionsActionEnabled;
    private final ConfigurationService configurationService;
    private final CloudwatchMetricsService cloudwatchMetricsService;

    public AccountInterventionService(ConfigurationService configService) {
        this(
                configService,
                HttpClient.newHttpClient(),
                new CloudwatchMetricsService(),
                new AuditService(configService));
    }

    public AccountInterventionService(
            ConfigurationService configService,
            CloudwatchMetricsService cloudwatchMetricsService,
            AuditService auditService) {
        this(configService, HttpClient.newHttpClient(), cloudwatchMetricsService, auditService);
    }

    public AccountInterventionService(
            ConfigurationService configService,
            HttpClient httpClient,
            CloudwatchMetricsService cloudwatchMetricsService,
            AuditService auditService) {
        this.configurationService = configService;
        this.accountInterventionServiceURI = configService.getAccountInterventionServiceURI();
        this.accountInterventionsCallEnabled =
                configurationService.isAccountInterventionServiceCallEnabled();
        this.accountInterventionsActionEnabled =
                configurationService.isAccountInterventionServiceActionEnabled();
        this.httpClient = httpClient;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.auditService = auditService;
    }

    public AccountInterventionStatus getAccountStatus(String internalPairwiseSubjectId)
            throws AccountInterventionException {
        return getAccountStatus(internalPairwiseSubjectId, null);
    }

    public AccountInterventionStatus getAccountStatus(
            String internalPairwiseSubjectId, AuditContext auditContext)
            throws AccountInterventionException {

        if (accountInterventionsCallEnabled) {
            try {
                var status = retrieveAccountStatus(internalPairwiseSubjectId);
                if (accountInterventionsActionEnabled) {
                    if (auditContext == null) {
                        throw new AccountInterventionException(
                                "Account intervention Audit enabled, but no AuditContext provided");
                    }
                    auditService.submitAuditEvent(AIS_RESPONSE_RECEIVED, auditContext);
                }

                return status;

            } catch (IOException | Json.JsonException e) {
                return handleException(e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return handleException(e);
            }
        }

        return noInterventionResponse();
    }

    private AccountInterventionStatus handleException(Exception e) {
        if (accountInterventionsActionEnabled) {
            throw new AccountInterventionException(
                    "Problem communicating with Account Intervention Service", e);
        }
        LOG.warn("Problem communicating with Account Intervention Service " + e);
        return noInterventionResponse();
    }

    private AccountInterventionStatus retrieveAccountStatus(String internalPairwiseSubjectId)
            throws IOException, InterruptedException, Json.JsonException {

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

        var accountInterventionStatus = response.state();
        incrementCloudwatchMetrics(accountInterventionStatus);

        return accountInterventionStatus;
    }

    public void doAccountIntervention(AccountInterventionStatus accountInterventionStatus) {
        if (accountInterventionStatus.blocked()) {
            LOG.info("Account is blocked");
            // TODO: (ATO-171) back channel logout + (ATO-170) redirect to blocked page
        } else if (accountInterventionStatus.suspended()
                || accountInterventionStatus.resetPassword()
                || accountInterventionStatus.reproveIdentity()) {
            LOG.info(
                    "Account is suspended, requires a password reset, or requires identity to be reproved");
            // TODO: (ATO-171) back channel logout + (ATO-170) redirect to suspended
            // page
        }
    }

    private void incrementCloudwatchMetrics(AccountInterventionStatus accountInterventionStatus) {
        cloudwatchMetricsService.incrementCounter(
                "AISResult",
                Map.of(
                        "blocked", String.valueOf(accountInterventionStatus.blocked()),
                        "suspended", String.valueOf(accountInterventionStatus.suspended()),
                        "resetPassword", String.valueOf(accountInterventionStatus.resetPassword()),
                        "reproveIdentity",
                                String.valueOf(accountInterventionStatus.reproveIdentity())));
    }

    private static AccountInterventionStatus noInterventionResponse() {
        return new AccountInterventionStatus(false, false, false, false);
    }
}
