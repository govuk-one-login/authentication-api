package uk.gov.di.authentication.ipv.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.entity.IdentityProgressStatus;
import uk.gov.di.orchestration.audit.AuditContext;
import uk.gov.di.orchestration.shared.entity.OrchIdentityCredentials;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.helper.Constants.CLIENT_SESSION_ID;
import static uk.gov.di.orchestration.sharedtest.helper.Constants.ENVIRONMENT;

class IdentityProgressServiceTest {
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoIdentityService dynamoIdentityService = mock(DynamoIdentityService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final IdentityProgressService.Sleeper sleeper = millis -> {};
    private final AuditContext auditContext = mock(AuditContext.class);
    private IdentityProgressService identityProgressService;

    @BeforeEach
    void setup() {
        when(configurationService.getEnvironment()).thenReturn(ENVIRONMENT);
        when(configurationService.getSyncWaitForSpotTimeout()).thenReturn(5000L);
        identityProgressService =
                new IdentityProgressService(
                        configurationService,
                        dynamoIdentityService,
                        auditService,
                        cloudwatchMetricsService,
                        sleeper);
    }

    @Test
    void shouldReturnCompletedStatusWhenCredentialsPresentWithCoreIdentityJwtOnFirstAttempt()
            throws Exception {
        when(dynamoIdentityService.getIdentityCredentials(CLIENT_SESSION_ID))
                .thenReturn(credentialsCompleted());

        var status = identityProgressService.pollForStatus(CLIENT_SESSION_ID, auditContext);

        assertEquals(IdentityProgressStatus.COMPLETED, status);
        verifyCloudwatchMetricIncrements(status);
        verifyAuditEventSubmitted();
    }

    @Test
    void shouldReturnCompletedStatusWhenCredentialsPresentWithCoreIdentityJwtOnSecondAttempt()
            throws Exception {
        when(dynamoIdentityService.getIdentityCredentials(CLIENT_SESSION_ID))
                .thenReturn(credentialsProcessing())
                .thenReturn(credentialsCompleted());

        var status = identityProgressService.pollForStatus(CLIENT_SESSION_ID, auditContext);

        assertEquals(IdentityProgressStatus.COMPLETED, status);
        verifyCloudwatchMetricIncrements(status);
        verifyAuditEventSubmitted();
    }

    @Test
    void shouldReturnNoEntryStatusWhenNoCredentialsFoundOnFirstAttempt() throws Exception {
        when(dynamoIdentityService.getIdentityCredentials(CLIENT_SESSION_ID))
                .thenReturn(credentialsNotFound());

        var status = identityProgressService.pollForStatus(CLIENT_SESSION_ID, auditContext);

        assertEquals(IdentityProgressStatus.NO_ENTRY, status);
        verifyCloudwatchMetricIncrements(status);
        verifyAuditEventSubmitted();
    }

    @Test
    void shouldReturnErrorStatusWhenNoCredentialsFoundOnSecondAttempt() throws Exception {
        when(dynamoIdentityService.getIdentityCredentials(CLIENT_SESSION_ID))
                .thenReturn(credentialsProcessing())
                .thenReturn(credentialsNotFound());

        var status = identityProgressService.pollForStatus(CLIENT_SESSION_ID, auditContext);

        assertEquals(IdentityProgressStatus.ERROR, status);
        verifyCloudwatchMetricIncrements(status);
        verifyAuditEventSubmitted();
    }

    @Test
    void shouldReturnErrorStatusWhenMaxRetriesHasBeenReached() throws Exception {
        when(dynamoIdentityService.getIdentityCredentials(CLIENT_SESSION_ID))
                .thenReturn(credentialsProcessing());

        var status = identityProgressService.pollForStatus(CLIENT_SESSION_ID, auditContext);

        assertEquals(IdentityProgressStatus.ERROR, status);
        verifyCloudwatchMetricIncrements(status);
        verifyAuditEventSubmitted();
    }

    private static Optional<OrchIdentityCredentials> credentialsNotFound() {
        return Optional.empty();
    }

    private static Optional<OrchIdentityCredentials> credentialsProcessing() {
        return Optional.of(new OrchIdentityCredentials());
    }

    private static Optional<OrchIdentityCredentials> credentialsCompleted() {
        return Optional.of(new OrchIdentityCredentials().withCoreIdentityJWT("test-jwt"));
    }

    private void verifyCloudwatchMetricIncrements(IdentityProgressStatus status) {
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "ProcessingIdentity",
                        Map.of(
                                "Environment",
                                configurationService.getEnvironment(),
                                "Status",
                                status.toString()));
    }

    private void verifyAuditEventSubmitted() {
        verify(auditService)
                .submitAuditEvent(IPVAuditableEvent.PROCESSING_IDENTITY_REQUEST, auditContext);
    }
}
