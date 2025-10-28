package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.audit.AuditContext;
import uk.gov.di.orchestration.shared.entity.AccountIntervention;
import uk.gov.di.orchestration.shared.entity.AccountInterventionResponse;
import uk.gov.di.orchestration.shared.entity.AccountInterventionState;
import uk.gov.di.orchestration.shared.exceptions.AccountInterventionException;
import uk.gov.di.orchestration.shared.helpers.HttpClientHelper;
import uk.gov.di.orchestration.shared.serialization.Json;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
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
                HttpClientHelper.newInstrumentedHttpClient(),
                new CloudwatchMetricsService(),
                new AuditService(configService));
    }

    public AccountInterventionService(
            ConfigurationService configService,
            CloudwatchMetricsService cloudwatchMetricsService,
            AuditService auditService) {
        this(
                configService,
                HttpClientHelper.newInstrumentedHttpClient(),
                cloudwatchMetricsService,
                auditService);
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

    public AccountIntervention getAccountIntervention(String internalPairwiseSubjectId)
            throws AccountInterventionException {
        return getAccountIntervention(internalPairwiseSubjectId, 0L, null);
    }

    public AccountIntervention getAccountIntervention(
            String internalPairwiseSubjectId, AuditContext auditContext)
            throws AccountInterventionException {
        return getAccountIntervention(internalPairwiseSubjectId, 0L, auditContext);
    }

    public AccountIntervention getAccountIntervention(
            String internalPairwiseSubjectId, Long passwordResetTime, AuditContext auditContext)
            throws AccountInterventionException {

        if (accountInterventionsCallEnabled) {
            try {
                AccountIntervention accountIntervention =
                        retrieveAccountIntervention(internalPairwiseSubjectId, passwordResetTime);
                if (accountInterventionsActionEnabled) {
                    if (auditContext == null) {
                        throw new AccountInterventionException(
                                "Account intervention Audit enabled, but no AuditContext provided");
                    }
                    auditService.submitAuditEvent(
                            AIS_RESPONSE_RECEIVED,
                            addStatusMetadata(auditContext, accountIntervention));
                }

                return accountIntervention;

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
            AuditContext auditContext, AccountIntervention intervention) {
        var existingMetadataPairs = auditContext.metadataPairs().stream();
        var statusMetadataPairs =
                Stream.of(
                        pair("blocked", intervention.getBlocked()),
                        pair("suspended", intervention.getSuspended()),
                        pair("resetPassword", intervention.getResetPassword()),
                        pair("reproveIdentity", intervention.getReproveIdentity()));
        var metadataPairs = Stream.concat(existingMetadataPairs, statusMetadataPairs).toList();

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

    private AccountIntervention handleException(Exception e) {
        cloudwatchMetricsService.incrementCounter(
                configurationService.getAccountInterventionsErrorMetricName(),
                Map.of(
                        "Environment",
                        configurationService.getEnvironment(),
                        "AbortOnError",
                        String.valueOf(acountInterventionsAbortOnError)));
        if (accountInterventionsActionEnabled && acountInterventionsAbortOnError) {
            String errorMessage =
                    "Problem communicating with Account Intervention Service. Aborting user journey.";
            LOG.error(errorMessage, e);
            throw new AccountInterventionException(errorMessage, e);
        }
        LOG.warn(
                "Problem communicating with Account Intervention Service. Assuming no intervention and continuing with user journey.",
                e);
        return noInterventionResponse();
    }

    private AccountIntervention retrieveAccountIntervention(
            String internalPairwiseSubjectId, Long passwordResetTime)
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

        HttpResponse<String> httpResponse = sendRequestToAis(request);
        AccountInterventionResponse response = serializeResponse(httpResponse);
        AccountIntervention accountIntervention =
                new AccountIntervention(
                        response.intervention(), response.state(), passwordResetTime);

        incrementCloudwatchMetrics(accountIntervention);
        return accountIntervention;
    }

    private HttpResponse<String> sendRequestToAis(HttpRequest request) {
        HttpResponse<String> httpResponse = null;
        var start = System.nanoTime();
        try {
            httpResponse = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            logAndThrowAccountInterventionException(
                    "Failed to send request to Account Intervention Service.");
        }
        var durationMs = (System.nanoTime() - start) / 1_000_000L;
        if (httpResponse != null) {
            instrumentResponse(durationMs, Integer.toString(httpResponse.statusCode()));
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

    private AccountInterventionResponse serializeResponse(HttpResponse<String> httpResponse) {
        AccountInterventionResponse accountInterventionResponse = null;
        try {
            accountInterventionResponse =
                    SerializationService.getInstance()
                            .readValue(httpResponse.body(), AccountInterventionResponse.class);
        } catch (Exception e) {
            logAndThrowAccountInterventionException("Failed to serialize AIS response body.", e);
        }
        if (Objects.isNull(accountInterventionResponse)) {
            logAndThrowAccountInterventionException("Account Intervention Status is null.");
        }
        return accountInterventionResponse;
    }

    private void instrumentResponse(double duration, String status) {
        cloudwatchMetricsService.putEmbeddedValue(
                "AISResponseTimeMs", duration, Map.of("statusCode", status));
    }

    private void incrementCloudwatchMetrics(AccountIntervention intervention) {
        cloudwatchMetricsService.incrementCounter(
                "AISResult",
                Map.of(
                        "blocked",
                        String.valueOf(intervention.getBlocked()),
                        "suspended",
                        String.valueOf(intervention.getSuspended()),
                        "resetPassword",
                        String.valueOf(intervention.getResetPassword()),
                        "reproveIdentity",
                        String.valueOf(intervention.getReproveIdentity())));
    }

    private static AccountIntervention noInterventionResponse() {
        return new AccountIntervention(new AccountInterventionState(false, false, false, false));
    }

    private void logAndThrowAccountInterventionException(String message, Exception cause) {
        LOG.error(message, cause);
        throw new AccountInterventionException(message, cause);
    }

    private void logAndThrowAccountInterventionException(String message) {
        LOG.error(message);
        throw new AccountInterventionException(message);
    }
}
