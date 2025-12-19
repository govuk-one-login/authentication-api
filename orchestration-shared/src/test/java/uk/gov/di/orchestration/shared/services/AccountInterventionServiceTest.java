package uk.gov.di.orchestration.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import uk.gov.di.orchestration.audit.AuditContext;
import uk.gov.di.orchestration.shared.domain.AuditableEvent;
import uk.gov.di.orchestration.shared.entity.AccountIntervention;
import uk.gov.di.orchestration.shared.exceptions.AccountInterventionException;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Arrays;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.domain.AccountInterventionsAuditableEvent.AIS_RESPONSE_RECEIVED;

// QualityGateUnitTest
class AccountInterventionServiceTest {
    private final ConfigurationService config = mock(ConfigurationService.class);
    private final HttpClient httpClient = mock(HttpClient.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final AuditService auditService = mock(AuditService.class);

    private static final String ACCOUNT_INTERVENTION_SERVICE_RESPONSE_SUSPEND_REPROVE =
            """
                    {
                        "intervention": {
                            "updatedAt": 1696969322935,
                            "appliedAt": 1696869005821,
                            "sentAt": 1696869003456,
                            "description": "AIS_USER_PASSWORD_RESET_AND_IDENTITY_REVERIFIED",
                            "reprovedIdentityAt": 1696969322935,
                            "resetPasswordAt": 1696969322935
                        },
                        "state": {
                            "blocked": false,
                            "suspended": true,
                            "reproveIdentity": true,
                            "resetPassword": false
                        },
                        "auditLevel": "standard",
                        "history": []
                    }
                    """;

    private static final String ACCOUNT_INTERVENTION_SERVICE_RESPONSE_WITHOUT_OPTIONAL_FIELDS =
            """
                    {
                        "intervention": {
                            "updatedAt": 1696969322935,
                            "appliedAt": 1696869005821,
                            "sentAt": 1696869003456,
                            "description": "AIS_USER_PASSWORD_RESET_AND_IDENTITY_REVERIFIED"
                        },
                        "state": {
                            "blocked": false,
                            "suspended": true,
                            "reproveIdentity": true,
                            "resetPassword": false
                        },
                        "auditLevel": "standard",
                        "history": []
                    }
                    """;

    private static String BASE_AIS_URL = "http://example.com/environment";
    private static AuditContext someAuditContext =
            new AuditContext(
                    "some-client-session-id",
                    "some-session-id",
                    "some-client-id",
                    "some-subject-id",
                    "some-email",
                    "some-ip-address",
                    "some-phone-number",
                    "some-persistent-session-id");
    private static final String ENVIRONMENT = "test-environment";

    @BeforeEach
    void setup() throws URISyntaxException {
        when(config.getAccountInterventionServiceURI()).thenReturn(new URI(BASE_AIS_URL));
        when(config.isAccountInterventionServiceCallEnabled()).thenReturn(true);
        when(config.isAccountInterventionServiceActionEnabled()).thenReturn(false);
        when(config.getEnvironment()).thenReturn(ENVIRONMENT);
        when(config.getAccountInterventionServiceCallTimeout()).thenReturn(3000L);
    }

    // QualityGateRegressionTest
    @Test
    void shouldConstructWellFormedRequestToAccountInterventionService()
            throws IOException, InterruptedException {

        var internalPairwiseSubjectId = "some-internal-subject-id";
        var ais =
                new AccountInterventionService(
                        config, httpClient, cloudwatchMetricsService, auditService);
        var httpResponse = mock(HttpResponse.class);
        var httpRequestCaptor = ArgumentCaptor.forClass(HttpRequest.class);

        when(httpClient.send(any(), any())).thenReturn(httpResponse);
        when(httpResponse.body()).thenReturn(ACCOUNT_INTERVENTION_SERVICE_RESPONSE_SUSPEND_REPROVE);

        ais.getAccountIntervention(internalPairwiseSubjectId);

        verify(httpClient).send(httpRequestCaptor.capture(), any());
        var requestUri = httpRequestCaptor.getValue();

        assertEquals(
                BASE_AIS_URL + "/v1/ais/" + internalPairwiseSubjectId, requestUri.uri().toString());
    }

    // QualityGateRegressionTest
    @Test
    void shouldReturnAccountIntervention() throws IOException, InterruptedException {

        var internalPairwiseSubjectId = "some-internal-subject-id";
        var accountInterventionService =
                new AccountInterventionService(
                        config, httpClient, cloudwatchMetricsService, auditService);
        var httpResponse = mock(HttpResponse.class);

        when(httpClient.send(any(), any())).thenReturn(httpResponse);
        when(httpResponse.body()).thenReturn(ACCOUNT_INTERVENTION_SERVICE_RESPONSE_SUSPEND_REPROVE);
        when(httpResponse.statusCode()).thenReturn(200);

        AccountIntervention intervention =
                accountInterventionService.getAccountIntervention(internalPairwiseSubjectId);

        assertFalse(intervention.getBlocked());
        assertTrue(intervention.getSuspended());
        assertTrue(intervention.getReproveIdentity());
        assertFalse(intervention.getResetPassword());

        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "AISResult",
                        Map.of(
                                "blocked", "false",
                                "suspended", "true",
                                "resetPassword", "false",
                                "reproveIdentity", "true"));
    }

    // QualityGateRegressionTest
    @Test
    void shouldReturnAccountInterventionWhenOptionalFieldsAreNotPresentInResponse()
            throws IOException, InterruptedException {

        var internalPairwiseSubjectId = "some-internal-subject-id";
        var accountInterventionService =
                new AccountInterventionService(
                        config, httpClient, cloudwatchMetricsService, auditService);
        var httpResponse = mock(HttpResponse.class);

        when(httpClient.send(any(), any())).thenReturn(httpResponse);
        when(httpResponse.body())
                .thenReturn(ACCOUNT_INTERVENTION_SERVICE_RESPONSE_WITHOUT_OPTIONAL_FIELDS);
        when(httpResponse.statusCode()).thenReturn(200);

        AccountIntervention intervention =
                accountInterventionService.getAccountIntervention(internalPairwiseSubjectId);

        assertFalse(intervention.getBlocked());
        assertTrue(intervention.getSuspended());
        assertTrue(intervention.getReproveIdentity());
        assertFalse(intervention.getResetPassword());

        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "AISResult",
                        Map.of(
                                "blocked", "false",
                                "suspended", "true",
                                "resetPassword", "false",
                                "reproveIdentity", "true"));
    }

    // QualityGateRegressionTest
    @Test
    void shouldReturnAccountStatusAllClearWhenDisabled() {

        when(config.isAccountInterventionServiceCallEnabled()).thenReturn(false);

        var internalPairwiseSubjectId = "some-internal-subject-id";
        var ais =
                new AccountInterventionService(
                        config, httpClient, cloudwatchMetricsService, auditService);
        AccountIntervention intervention = ais.getAccountIntervention(internalPairwiseSubjectId);

        verifyNoInteractions(httpClient);

        assertFalse(intervention.getBlocked());
        assertFalse(intervention.getSuspended());
        assertFalse(intervention.getReproveIdentity());
        assertFalse(intervention.getResetPassword());
    }

    // QualityGateRegressionTest
    @Test
    void
            shouldNotThrowAccountInterventionExceptionWhenExceptionThrownByHttpClientAndAbortFlagIsOff()
                    throws IOException, InterruptedException {

        when(config.isAccountInterventionServiceActionEnabled()).thenReturn(true);
        when(config.abortOnAccountInterventionsErrorResponse()).thenReturn(false);

        var internalPairwiseSubjectId = "some-internal-subject-id";
        var accountInterventionService =
                new AccountInterventionService(
                        config, httpClient, cloudwatchMetricsService, auditService);

        when(httpClient.send(any(), any())).thenThrow(new IOException("Test IO Exception"));

        assertDoesNotThrow(
                () -> accountInterventionService.getAccountIntervention(internalPairwiseSubjectId));
    }

    // QualityGateRegressionTest
    @Test
    void shouldThrowAccountInterventionExceptionWhenExceptionThrownByHttpClientAndAbortFlagIsOn()
            throws IOException, InterruptedException {

        when(config.isAccountInterventionServiceActionEnabled()).thenReturn(true);
        when(config.abortOnAccountInterventionsErrorResponse()).thenReturn(true);
        when(config.getAccountInterventionsErrorMetricName()).thenReturn("AISException");

        var internalPairwiseSubjectId = "some-internal-subject-id";
        var accountInterventionService =
                new AccountInterventionService(
                        config, httpClient, cloudwatchMetricsService, auditService);

        when(httpClient.send(any(), any())).thenThrow(new IOException("Test IO Exception"));

        assertThrows(
                AccountInterventionException.class,
                () -> accountInterventionService.getAccountIntervention(internalPairwiseSubjectId));

        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "AISException", Map.of("Environment", ENVIRONMENT, "AbortOnError", "true"));
    }

    // QualityGateRegressionTest
    @Test
    void shouldSendAuditEventWhenServiceCallAndActionEnabled()
            throws IOException, InterruptedException {

        when(config.isAccountInterventionServiceActionEnabled()).thenReturn(true);

        var internalPairwiseSubjectId = "some-internal-subject-id";
        var accountInterventionService =
                new AccountInterventionService(
                        config, httpClient, cloudwatchMetricsService, auditService);
        var httpResponse = mock(HttpResponse.class);
        var auditEventNameCaptor = ArgumentCaptor.forClass(AuditableEvent.class);
        var auditContextCaptor = ArgumentCaptor.forClass(AuditContext.class);

        when(httpClient.send(any(), any())).thenReturn(httpResponse);
        when(httpResponse.body()).thenReturn(ACCOUNT_INTERVENTION_SERVICE_RESPONSE_SUSPEND_REPROVE);
        when(httpResponse.statusCode()).thenReturn(200);

        accountInterventionService.getAccountIntervention(
                internalPairwiseSubjectId, someAuditContext);

        var expectedAuditContext =
                new AuditContext(
                        someAuditContext.clientSessionId(),
                        someAuditContext.sessionId(),
                        someAuditContext.clientId(),
                        someAuditContext.subjectId(),
                        someAuditContext.email(),
                        someAuditContext.ipAddress(),
                        someAuditContext.phoneNumber(),
                        someAuditContext.persistentSessionId(),
                        AuditService.MetadataPair.pair("blocked", false),
                        AuditService.MetadataPair.pair("suspended", true),
                        AuditService.MetadataPair.pair("resetPassword", false),
                        AuditService.MetadataPair.pair("reproveIdentity", true));

        verify(auditService)
                .submitAuditEvent(auditEventNameCaptor.capture(), auditContextCaptor.capture());
        assertEquals(AIS_RESPONSE_RECEIVED, auditEventNameCaptor.getValue());
        assertMatchingAuditContext(expectedAuditContext, auditContextCaptor.getValue());
    }

    // QualityGateRegressionTest
    @Test
    void shouldNotSendAuditEventWhenServiceEnabledAndActionDisabled()
            throws IOException, InterruptedException {

        var internalPairwiseSubjectId = "some-internal-subject-id";
        var accountInterventionService =
                new AccountInterventionService(
                        config, httpClient, cloudwatchMetricsService, auditService);
        var httpResponse = mock(HttpResponse.class);

        when(httpClient.send(any(), any())).thenReturn(httpResponse);
        when(httpResponse.body()).thenReturn(ACCOUNT_INTERVENTION_SERVICE_RESPONSE_SUSPEND_REPROVE);

        accountInterventionService.getAccountIntervention(
                internalPairwiseSubjectId, someAuditContext);

        verifyNoInteractions(auditService);
    }

    // QualityGateRegressionTest
    @Test
    void shouldThrowExceptionWhenNullAuditContextSuppliedAndActionEnabledAndAbortEnabled()
            throws IOException, InterruptedException {

        when(config.isAccountInterventionServiceActionEnabled()).thenReturn(true);
        when(config.abortOnAccountInterventionsErrorResponse()).thenReturn(true);

        var internalPairwiseSubjectId = "some-internal-subject-id";
        var accountInterventionService =
                new AccountInterventionService(
                        config, httpClient, cloudwatchMetricsService, auditService);
        var httpResponse = mock(HttpResponse.class);

        when(httpClient.send(any(), any())).thenReturn(httpResponse);
        when(httpResponse.body()).thenReturn(ACCOUNT_INTERVENTION_SERVICE_RESPONSE_SUSPEND_REPROVE);

        assertThrows(
                AccountInterventionException.class,
                () ->
                        accountInterventionService.getAccountIntervention(
                                internalPairwiseSubjectId, null));
    }

    private void assertMatchingAuditContext(AuditContext expected, AuditContext actual) {
        assertEquals(expected.clientSessionId(), actual.clientSessionId());
        assertEquals(expected.sessionId(), actual.sessionId());
        assertEquals(expected.clientId(), actual.clientId());
        assertEquals(expected.subjectId(), actual.subjectId());
        assertEquals(expected.email(), actual.email());
        assertEquals(expected.ipAddress(), actual.ipAddress());
        assertEquals(expected.phoneNumber(), actual.phoneNumber());
        assertEquals(expected.persistentSessionId(), actual.persistentSessionId());
        assertTrue(Arrays.deepEquals(expected.metadataPairs(), actual.metadataPairs()));
    }
}
