package uk.gov.di.orchestration.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import uk.gov.di.orchestration.audit.AuditContext;
import uk.gov.di.orchestration.shared.domain.AuditableEvent;
import uk.gov.di.orchestration.shared.exceptions.AccountInterventionException;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.domain.AccountInterventionsAuditableEvent.AIS_RESPONSE_RECEIVED;

class AccountInterventionServiceTest {

    private final ConfigurationService config = mock(ConfigurationService.class);
    private final HttpClient httpClient = mock(HttpClient.class);
    private final AuditService auditService = mock(AuditService.class);

    private static String ACCOUNT_INTERVENTION_SERVICE_RESPONSE_SUSPEND_REPROVE =
            """
            {
                "intervention": {
                    "updatedAt": 1696969322935,
                    "appliedAt": 1696869005821,
                    "sentAt": 1696869003456,
                    "description": "AIS_USER_PASSWORD_RESET_AND_IDENTITY_REVERIFIED",
                    "reprovedIdentityAt": 1696969322935
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

    private static String BASE_AIS_URL = "http://example.com/somepath/";
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

    @BeforeEach
    void setup() throws URISyntaxException {
        when(config.getAccountInterventionServiceURI()).thenReturn(new URI(BASE_AIS_URL));
        when(config.isAccountInterventionServiceEnabled()).thenReturn(true);
        when(config.isAccountInterventionServiceAuditEnabled()).thenReturn(false);
    }

    @Test
    void shouldConstructWellFormedRequestToAccountInterventionService()
            throws IOException, InterruptedException {

        var internalPairwiseSubjectId = "some-internal-subject-id";
        var ais = new AccountInterventionService(config, httpClient, auditService);
        var httpResponse = mock(HttpResponse.class);
        var httpRequestCaptor = ArgumentCaptor.forClass(HttpRequest.class);

        when(httpClient.send(any(), any())).thenReturn(httpResponse);
        when(httpResponse.body()).thenReturn("{\"foo\": \"bar\"}");

        ais.getAccountStatus(internalPairwiseSubjectId);

        verify(httpClient).send(httpRequestCaptor.capture(), any());
        var requestUri = httpRequestCaptor.getValue();

        assertEquals(BASE_AIS_URL + internalPairwiseSubjectId, requestUri.uri().toString());
    }

    @Test
    void shouldReturnAccountStatus() throws IOException, InterruptedException {

        var internalPairwiseSubjectId = "some-internal-subject-id";
        var accountInterventionService =
                new AccountInterventionService(config, httpClient, auditService);
        var httpResponse = mock(HttpResponse.class);

        when(httpClient.send(any(), any())).thenReturn(httpResponse);
        when(httpResponse.body()).thenReturn(ACCOUNT_INTERVENTION_SERVICE_RESPONSE_SUSPEND_REPROVE);

        var status = accountInterventionService.getAccountStatus(internalPairwiseSubjectId);

        assertEquals(false, status.blocked());
        assertEquals(true, status.suspended());
        assertEquals(true, status.reproveIdentity());
        assertEquals(false, status.resetPassword());
    }

    @Test
    void shouldReturnAccountStatusAllClearWhenDisabled() {

        when(config.isAccountInterventionServiceEnabled()).thenReturn(false);

        var internalPairwiseSubjectId = "some-internal-subject-id";
        var ais = new AccountInterventionService(config, httpClient, auditService);
        var status = ais.getAccountStatus(internalPairwiseSubjectId);

        verifyNoInteractions(httpClient);

        assertEquals(false, status.blocked());
        assertEquals(false, status.suspended());
        assertEquals(false, status.reproveIdentity());
        assertEquals(false, status.resetPassword());
    }

    @Test
    void shouldThrowAccountInterventionExceptionWhenExceptionThrownByHttpClient()
            throws IOException, InterruptedException {

        var internalPairwiseSubjectId = "some-internal-subject-id";
        var accountInterventionService =
                new AccountInterventionService(config, httpClient, auditService);

        when(httpClient.send(any(), any())).thenThrow(new IOException("Test IO Exception"));

        assertThrows(
                AccountInterventionException.class,
                () -> {
                    accountInterventionService.getAccountStatus(internalPairwiseSubjectId);
                });
    }

    @Test
    void shouldSendAuditEventWhenServiceAndAuditEnabled() throws IOException, InterruptedException {

        when(config.isAccountInterventionServiceAuditEnabled()).thenReturn(true);

        var internalPairwiseSubjectId = "some-internal-subject-id";
        var accountInterventionService =
                new AccountInterventionService(config, httpClient, auditService);
        var httpResponse = mock(HttpResponse.class);
        var auditEventNameCaptor = ArgumentCaptor.forClass(AuditableEvent.class);
        var auditContextCaptor = ArgumentCaptor.forClass(AuditContext.class);

        when(httpClient.send(any(), any())).thenReturn(httpResponse);
        when(httpResponse.body()).thenReturn("{\"foo\": \"bar\"}");

        accountInterventionService.getAccountStatus(internalPairwiseSubjectId, someAuditContext);

        verify(auditService)
                .submitAuditEvent(auditEventNameCaptor.capture(), auditContextCaptor.capture());
        assertEquals(AIS_RESPONSE_RECEIVED, auditEventNameCaptor.getValue());
        assertEquals(someAuditContext, auditContextCaptor.getValue());
    }

    @Test
    void shouldNotSendAuditEventWhenServiceEnabledAndAuditDisabled()
            throws IOException, InterruptedException {

        var internalPairwiseSubjectId = "some-internal-subject-id";
        var accountInterventionService =
                new AccountInterventionService(config, httpClient, auditService);
        var httpResponse = mock(HttpResponse.class);

        when(httpClient.send(any(), any())).thenReturn(httpResponse);
        when(httpResponse.body()).thenReturn("{\"foo\": \"bar\"}");

        accountInterventionService.getAccountStatus(internalPairwiseSubjectId, someAuditContext);

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldThrowExceptionWhenNullAuditContextSuppliedAndAuditEnabled()
            throws IOException, InterruptedException {

        when(config.isAccountInterventionServiceAuditEnabled()).thenReturn(true);

        var internalPairwiseSubjectId = "some-internal-subject-id";
        var accountInterventionService =
                new AccountInterventionService(config, httpClient, auditService);
        var httpResponse = mock(HttpResponse.class);

        when(httpClient.send(any(), any())).thenReturn(httpResponse);
        when(httpResponse.body()).thenReturn("{\"foo\": \"bar\"}");

        assertThrows(
                AccountInterventionException.class,
                () -> {
                    accountInterventionService.getAccountStatus(internalPairwiseSubjectId, null);
                });
    }
}
