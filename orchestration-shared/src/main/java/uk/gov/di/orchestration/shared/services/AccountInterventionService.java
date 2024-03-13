package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.audit.AuditContext;
import uk.gov.di.orchestration.shared.entity.AccountInterventionResponse;
import uk.gov.di.orchestration.shared.entity.AccountInterventionState;
import uk.gov.di.orchestration.shared.exceptions.AccountInterventionException;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.AuditService.MetadataPair;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

import static uk.gov.di.orchestration.shared.domain.AccountInterventionsAuditableEvent.AIS_RESPONSE_RECEIVED;
import static uk.gov.di.orchestration.shared.services.AuditService.MetadataPair.pair;

public class AccountInterventionService {

    private static final Logger LOG = LogManager.getLogger(AccountInterventionService.class);
    private final HttpClient httpClient;
    private final URI accountInterventionServiceURI;
    private final AuditService auditService;
    private final boolean accountInterventionsCallEnabled;
    private final boolean accountInterventionsActionEnabled;
    private final boolean acountInterventionsAbortOnError;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final ConfigurationService configurationService;

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
        this.accountInterventionServiceURI = configService.getAccountInterventionServiceURI();
        this.accountInterventionsCallEnabled =
                configService.isAccountInterventionServiceCallEnabled();
        this.accountInterventionsActionEnabled =
                configService.isAccountInterventionServiceActionEnabled();
        this.acountInterventionsAbortOnError =
                configService.abortOnAccountInterventionsErrorResponse();
        this.httpClient = httpClient;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.auditService = auditService;
        this.configurationService = configService;
    }

    public AccountInterventionState getAccountState(String internalPairwiseSubjectId)
            throws AccountInterventionException {
        return getAccountState(internalPairwiseSubjectId, null);
    }

    public AccountInterventionState getAccountState(
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
                    auditService.submitAuditEvent(
                            AIS_RESPONSE_RECEIVED, addStatusMetadata(auditContext, status));
                }

                return status;

            } catch (IOException | Json.JsonException | AccountInterventionException e) {
                return handleException(e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return handleException(e);
            }
        }

        return noInterventionResponse();
    }

    private static AuditContext addStatusMetadata(
            AuditContext auditContext, AccountInterventionState status) {
        var existingMetadataPairs = Arrays.stream(auditContext.metadataPairs());
        var statusMetadataPairs =
                Stream.of(
                        pair("blocked", status.blocked()),
                        pair("suspended", status.suspended()),
                        pair("resetPassword", status.resetPassword()),
                        pair("reproveIdentity", status.reproveIdentity()));
        var metadataPairs =
                Stream.concat(existingMetadataPairs, statusMetadataPairs)
                        .toArray(MetadataPair[]::new);

        return new AuditContext(
                auditContext.clientSessionId(),
                auditContext.sessionId(),
                auditContext.clientId(),
                auditContext.subjectId(),
                auditContext.email(),
                auditContext.ipAddress(),
                auditContext.phoneNumber(),
                auditContext.persistentSessionId(),
                metadataPairs);
    }

    private AccountInterventionState handleException(Exception e) {
        cloudwatchMetricsService.incrementCounter(
                configurationService.getAccountInterventionsErrorMetricName(),
                Map.of("Environment", configurationService.getEnvironment()));
        if (accountInterventionsActionEnabled && acountInterventionsAbortOnError) {
            throw new AccountInterventionException(
                    "Problem communicating with Account Intervention Service", e);
        }
        LOG.error(
                "Problem communicating with Account Intervention Service. Assuming no intervention. ",
                e);
        return noInterventionResponse();
    }

    private AccountInterventionState retrieveAccountStatus(String internalPairwiseSubjectId)
            throws IOException, InterruptedException, Json.JsonException {

        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(
                                accountInterventionServiceURI.resolve(
                                        accountInterventionServiceURI.getPath()
                                                + "/v1/ais/"
                                                + internalPairwiseSubjectId))
                        .timeout(
                                Duration.ofMillis(
                                        configurationService
                                                .getAccountInterventionServiceCallTimeout()))
                        .GET()
                        .build();

        HttpResponse<String> response = sendRequestToAis(request);
        AccountInterventionState accountInterventionState = serializeResponse(response);
        incrementCloudwatchMetrics(accountInterventionState);
        return accountInterventionState;
    }

    private HttpResponse<String> sendRequestToAis(HttpRequest request) {
        HttpResponse<String> httpResponse = null;
        try {
            httpResponse = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        } catch (IOException | InterruptedException e) {
            logAndThrowAccountInterventionException(
                    "Failed to send request to Account Intervention Service.");
        }
        validateResponse(httpResponse);
        return httpResponse;
    }

    private void validateResponse(HttpResponse<String> httpResponse) {
        if (Objects.isNull(httpResponse)) {
            logAndThrowAccountInterventionException(
                    "Account Intervention Service response is null. The request may have timed out.");
        }
        int responseStatus = httpResponse.statusCode();
        if (responseStatus < 200 || responseStatus > 299) {
            logAndThrowAccountInterventionException(
                    "Account Intervention Service responded with status code: " + responseStatus);
        }
    }

    private AccountInterventionState serializeResponse(HttpResponse<String> httpResponse) {
        AccountInterventionState accountInterventionState = null;
        try {
            var response =
                    SerializationService.getInstance()
                            .readValue(httpResponse.body(), AccountInterventionResponse.class);
            accountInterventionState = response.state();
        } catch (Exception e) {
            logAndThrowAccountInterventionException("Failed to serialize AIS response body.");
        }
        if (Objects.isNull(accountInterventionState)) {
            logAndThrowAccountInterventionException("Account Intervention Status is null.");
        }
        return accountInterventionState;
    }

    private void incrementCloudwatchMetrics(AccountInterventionState accountInterventionState) {
        cloudwatchMetricsService.incrementCounter(
                "AISResult",
                Map.of(
                        "blocked",
                        String.valueOf(accountInterventionState.blocked()),
                        "suspended",
                        String.valueOf(accountInterventionState.suspended()),
                        "resetPassword",
                        String.valueOf(accountInterventionState.resetPassword()),
                        "reproveIdentity",
                        String.valueOf(accountInterventionState.reproveIdentity())));
    }

    private static AccountInterventionState noInterventionResponse() {
        return new AccountInterventionState(false, false, false, false);
    }

    private void logAndThrowAccountInterventionException(String message) {
        LOG.error(message);
        throw new AccountInterventionException(message);
    }
}
