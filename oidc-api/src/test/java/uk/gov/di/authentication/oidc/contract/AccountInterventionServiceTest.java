package uk.gov.di.authentication.oidc.contract;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.DslPart;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit.MockServerConfig;
import au.com.dius.pact.consumer.junit5.PactConsumerTest;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.PactSpecVersion;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.audit.AuditContext;
import uk.gov.di.orchestration.shared.entity.AccountIntervention;
import uk.gov.di.orchestration.shared.entity.AccountInterventionStatus;
import uk.gov.di.orchestration.shared.exceptions.AccountInterventionException;
import uk.gov.di.orchestration.shared.services.*;

import java.net.URI;
import java.net.http.HttpClient;
import java.util.Map;

import static au.com.dius.pact.consumer.dsl.LambdaDsl.newJsonBody;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;
import static uk.gov.di.orchestration.shared.domain.AccountInterventionsAuditableEvent.AIS_RESPONSE_RECEIVED;

@PactConsumerTest
@MockServerConfig(hostInterface = "localhost", port = "1234")
class AccountInterventionServiceTest {
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final Metrics metrics = mock(Metrics.class);
    private final AuditService auditService = mock(AuditService.class);
    private final HttpClient httpClient = HttpClient.newHttpClient();
    private AccountInterventionService accountInterventionService;

    private static final String PROVIDER_NAME = "AccountInterventionServiceProvider";
    private static final String CONSUMER_NAME = "OrchAccountInterventionServiceConsumer";
    private static final String INTERNAL_PAIRWISE_SUBJECT_ID = "internal-pairwise-subject-id";
    private static final String INVALID_INTERNAL_PAIRWISE_SUBJECT_ID =
            "invalid-internal-pairwise-subject-id";
    private static final Long AIS_CALL_TIMEOUT = 3000L;
    private static final Long TIME_NOW = 1710867479881L;
    private static final Long TIME_LATER = TIME_NOW + 1000L;
    private static final boolean AIS_CALL_ENABLED = true;
    private static final boolean AIS_ACTION_ENABLED = true;
    private static final String AIS_ERROR_METRIC_NAME = "AISException";
    private static final String ENVIRONMENT = "contract-test";

    private final AuditContext auditContext =
            new AuditContext(
                    "test-client-session-id",
                    "test-session-id",
                    "test-client-id",
                    "test-subject-id",
                    "test-email-address",
                    "test-ip-address",
                    "test-phone-number",
                    "test-persistent-session-id");

    @BeforeEach
    void setup() {
        when(configService.isAccountInterventionServiceCallEnabled()).thenReturn(AIS_CALL_ENABLED);
        when(configService.isAccountInterventionServiceActionEnabled())
                .thenReturn(AIS_ACTION_ENABLED);
        when(configService.getAccountInterventionServiceCallTimeout()).thenReturn(AIS_CALL_TIMEOUT);
        when(configService.getAccountInterventionsErrorMetricName())
                .thenReturn(AIS_ERROR_METRIC_NAME);
        when(configService.getEnvironment()).thenReturn(ENVIRONMENT);
    }

    @Pact(provider = PROVIDER_NAME, consumer = CONSUMER_NAME)
    RequestResponsePact createNoInterventionPact(PactDslWithProvider builder) {
        return PactGenerator.successfulResponse(builder, false, false, false, false);
    }

    @Test
    @PactTestFor(
            providerName = PROVIDER_NAME,
            pactMethod = "createNoInterventionPact",
            pactVersion = PactSpecVersion.V3)
    void returnsNoInterventionWhenResponseIsNoIntervention(MockServer mockServer) {
        when(configService.getAccountInterventionServiceURI())
                .thenReturn(URI.create(mockServer.getUrl()));
        accountInterventionService =
                new AccountInterventionService(configService, httpClient, metrics, auditService);

        AccountIntervention intervention =
                accountInterventionService.getAccountIntervention(
                        INTERNAL_PAIRWISE_SUBJECT_ID, auditContext);

        assertAndVerifySuccessfulResponse(intervention, AccountInterventionStatus.NO_INTERVENTION);
    }

    @Pact(provider = PROVIDER_NAME, consumer = CONSUMER_NAME)
    RequestResponsePact createBlockedPact(PactDslWithProvider builder) {
        return PactGenerator.successfulResponse(builder, true, false, false, false);
    }

    @Test
    @PactTestFor(
            providerName = PROVIDER_NAME,
            pactMethod = "createBlockedPact",
            pactVersion = PactSpecVersion.V3)
    void returnsBlockedWhenResponseIsBlocked(MockServer mockServer) {
        when(configService.getAccountInterventionServiceURI())
                .thenReturn(URI.create(mockServer.getUrl()));
        accountInterventionService =
                new AccountInterventionService(configService, httpClient, metrics, auditService);

        AccountIntervention intervention =
                accountInterventionService.getAccountIntervention(
                        INTERNAL_PAIRWISE_SUBJECT_ID, auditContext);

        assertAndVerifySuccessfulResponse(intervention, AccountInterventionStatus.BLOCKED);
    }

    @Pact(provider = PROVIDER_NAME, consumer = CONSUMER_NAME)
    RequestResponsePact createSuspendedPact(PactDslWithProvider builder) {
        return PactGenerator.successfulResponse(builder, false, true, false, false);
    }

    @Test
    @PactTestFor(
            providerName = PROVIDER_NAME,
            pactMethod = "createSuspendedPact",
            pactVersion = PactSpecVersion.V3)
    void returnsSuspendedNoActionWhenResponseIsSuspended(MockServer mockServer) {
        when(configService.getAccountInterventionServiceURI())
                .thenReturn(URI.create(mockServer.getUrl()));
        accountInterventionService =
                new AccountInterventionService(configService, httpClient, metrics, auditService);

        AccountIntervention intervention =
                accountInterventionService.getAccountIntervention(
                        INTERNAL_PAIRWISE_SUBJECT_ID, auditContext);

        assertAndVerifySuccessfulResponse(
                intervention, AccountInterventionStatus.SUSPENDED_NO_ACTION);
    }

    @Pact(provider = PROVIDER_NAME, consumer = CONSUMER_NAME)
    RequestResponsePact createSuspendedReproveIdentityPact(PactDslWithProvider builder) {
        return PactGenerator.successfulResponse(builder, false, true, true, false);
    }

    @Test
    @PactTestFor(
            providerName = PROVIDER_NAME,
            pactMethod = "createSuspendedReproveIdentityPact",
            pactVersion = PactSpecVersion.V3)
    void returnsSuspendedReproveIdWhenResponseIsSuspendedReproveIdentity(MockServer mockServer) {
        when(configService.getAccountInterventionServiceURI())
                .thenReturn(URI.create(mockServer.getUrl()));
        accountInterventionService =
                new AccountInterventionService(configService, httpClient, metrics, auditService);

        AccountIntervention intervention =
                accountInterventionService.getAccountIntervention(
                        INTERNAL_PAIRWISE_SUBJECT_ID, auditContext);

        assertAndVerifySuccessfulResponse(
                intervention, AccountInterventionStatus.SUSPENDED_REPROVE_ID);
    }

    @Pact(provider = PROVIDER_NAME, consumer = CONSUMER_NAME)
    RequestResponsePact createSuspendedResetPasswordPact(PactDslWithProvider builder) {
        return PactGenerator.successfulResponse(builder, false, true, false, true);
    }

    @Test
    @PactTestFor(
            providerName = PROVIDER_NAME,
            pactMethod = "createSuspendedResetPasswordPact",
            pactVersion = PactSpecVersion.V3)
    void returnsSuspendedResetPasswordWhenResponseIsSuspendedResetPassword(MockServer mockServer) {
        when(configService.getAccountInterventionServiceURI())
                .thenReturn(URI.create(mockServer.getUrl()));
        accountInterventionService =
                new AccountInterventionService(configService, httpClient, metrics, auditService);

        AccountIntervention intervention =
                accountInterventionService.getAccountIntervention(
                        INTERNAL_PAIRWISE_SUBJECT_ID, auditContext);

        assertAndVerifySuccessfulResponse(
                intervention, AccountInterventionStatus.SUSPENDED_RESET_PASSWORD);
    }

    @Test
    @PactTestFor(
            providerName = PROVIDER_NAME,
            pactMethod = "createSuspendedResetPasswordPact",
            pactVersion = PactSpecVersion.V3)
    void returnsNoInterventionWhenResponseIsSuspendedResetPasswordAndPasswordWasRecentlyReset(
            MockServer mockServer) {
        when(configService.getAccountInterventionServiceURI())
                .thenReturn(URI.create(mockServer.getUrl()));
        accountInterventionService =
                new AccountInterventionService(configService, httpClient, metrics, auditService);

        AccountIntervention intervention =
                accountInterventionService.getAccountIntervention(
                        INTERNAL_PAIRWISE_SUBJECT_ID, TIME_LATER, auditContext);

        assertAndVerifySuccessfulResponse(intervention, AccountInterventionStatus.NO_INTERVENTION);
    }

    @Pact(provider = PROVIDER_NAME, consumer = CONSUMER_NAME)
    RequestResponsePact createSuspendedReproveIdentityResetPasswordPact(
            PactDslWithProvider builder) {
        return PactGenerator.successfulResponse(builder, false, true, true, true);
    }

    @Test
    @PactTestFor(
            providerName = PROVIDER_NAME,
            pactMethod = "createSuspendedReproveIdentityResetPasswordPact",
            pactVersion = PactSpecVersion.V3)
    void returnsSuspendedResetPasswordReproveIdWhenResponseIsSuspendedReproveIdentityResetPassword(
            MockServer mockServer) {
        when(configService.getAccountInterventionServiceURI())
                .thenReturn(URI.create(mockServer.getUrl()));
        accountInterventionService =
                new AccountInterventionService(configService, httpClient, metrics, auditService);

        AccountIntervention intervention =
                accountInterventionService.getAccountIntervention(
                        INTERNAL_PAIRWISE_SUBJECT_ID, auditContext);

        assertAndVerifySuccessfulResponse(
                intervention, AccountInterventionStatus.SUSPENDED_RESET_PASSWORD_REPROVE_ID);
    }

    @Test
    @PactTestFor(
            providerName = PROVIDER_NAME,
            pactMethod = "createSuspendedReproveIdentityResetPasswordPact",
            pactVersion = PactSpecVersion.V3)
    void
            returnsSuspendedReproveIdWhenResponseIsSuspendedReproveIdentityResetPasswordAndPasswordWasRecentlyReset(
                    MockServer mockServer) {
        when(configService.getAccountInterventionServiceURI())
                .thenReturn(URI.create(mockServer.getUrl()));
        accountInterventionService =
                new AccountInterventionService(configService, httpClient, metrics, auditService);

        AccountIntervention intervention =
                accountInterventionService.getAccountIntervention(
                        INTERNAL_PAIRWISE_SUBJECT_ID, TIME_LATER, auditContext);

        assertAndVerifySuccessfulResponse(
                intervention, AccountInterventionStatus.SUSPENDED_REPROVE_ID);
    }

    @Pact(provider = PROVIDER_NAME, consumer = CONSUMER_NAME)
    RequestResponsePact createInvalidPairwiseSubjectIdPact(PactDslWithProvider builder) {
        return builder.given("the internal pairwise subject id does not exist in the AIS database")
                .uponReceiving("A request for an account that does not exist")
                .path("/v1/ais/" + INVALID_INTERNAL_PAIRWISE_SUBJECT_ID)
                .method("GET")
                .willRespondWith()
                .status(200)
                .body(createAisResponseBody(false, false, false, false))
                .toPact();
    }

    @Test
    @PactTestFor(
            providerName = PROVIDER_NAME,
            pactMethod = "createInvalidPairwiseSubjectIdPact",
            pactVersion = PactSpecVersion.V3)
    void returnsNoInterventionWhenPairwiseSubjectIdIsInvalid(MockServer mockServer) {
        when(configService.getAccountInterventionServiceURI())
                .thenReturn(URI.create(mockServer.getUrl()));
        accountInterventionService =
                new AccountInterventionService(configService, httpClient, metrics, auditService);

        AccountIntervention intervention =
                accountInterventionService.getAccountIntervention(
                        INVALID_INTERNAL_PAIRWISE_SUBJECT_ID, auditContext);

        assertThat(intervention.getStatus(), equalTo(AccountInterventionStatus.NO_INTERVENTION));
    }

    @Pact(provider = PROVIDER_NAME, consumer = CONSUMER_NAME)
    RequestResponsePact createServerError500Pact(PactDslWithProvider builder) {
        return builder.given("AIS encounters an error and responds with 500 status")
                .uponReceiving("a valid request to the AIS API")
                .path("/v1/ais/" + INTERNAL_PAIRWISE_SUBJECT_ID)
                .method("GET")
                .willRespondWith()
                .status(500)
                .toPact();
    }

    @Test
    @PactTestFor(
            providerName = PROVIDER_NAME,
            pactMethod = "createServerError500Pact",
            pactVersion = PactSpecVersion.V3)
    void throwsErrorWhenResponseIsServerError500AndAbortFlagIsOn(MockServer mockServer) {
        when(configService.abortOnAccountInterventionsErrorResponse()).thenReturn(true);
        when(configService.getAccountInterventionServiceURI())
                .thenReturn(URI.create(mockServer.getUrl()));
        accountInterventionService =
                new AccountInterventionService(configService, httpClient, metrics, auditService);

        RuntimeException exception =
                assertThrows(
                        AccountInterventionException.class,
                        () ->
                                accountInterventionService.getAccountIntervention(
                                        INTERNAL_PAIRWISE_SUBJECT_ID, auditContext));
        assertEquals(
                "Problem communicating with Account Intervention Service. Aborting user journey.",
                exception.getMessage());
    }

    @Test
    @PactTestFor(
            providerName = PROVIDER_NAME,
            pactMethod = "createServerError500Pact",
            pactVersion = PactSpecVersion.V3)
    void returnsNoInterventionWhenResponseIsServerError500AndAbortFlagIsOff(MockServer mockServer) {
        when(configService.abortOnAccountInterventionsErrorResponse()).thenReturn(false);
        when(configService.getAccountInterventionServiceURI())
                .thenReturn(URI.create(mockServer.getUrl()));
        accountInterventionService =
                new AccountInterventionService(configService, httpClient, metrics, auditService);

        AccountIntervention intervention =
                accountInterventionService.getAccountIntervention(
                        INTERNAL_PAIRWISE_SUBJECT_ID, auditContext);

        assertThat(intervention.getStatus(), equalTo(AccountInterventionStatus.NO_INTERVENTION));
    }

    private static DslPart createAisResponseBody(
            boolean blocked, boolean suspended, boolean reproveIdentity, boolean resetPassword) {
        return newJsonBody(
                        (body) -> {
                            body.object(
                                    "intervention",
                                    (obj) -> {
                                        obj.numberType("appliedAt", TIME_NOW);
                                    });
                            body.object(
                                    "state",
                                    (obj) -> {
                                        obj.booleanValue("blocked", blocked);
                                        obj.booleanValue("suspended", suspended);
                                        obj.booleanValue("reproveIdentity", reproveIdentity);
                                        obj.booleanValue("resetPassword", resetPassword);
                                    });
                        })
                .build();
    }

    private void assertAndVerifySuccessfulResponse(
            AccountIntervention intervention, AccountInterventionStatus accountInterventionStatus) {

        assertThat(intervention.getStatus(), equalTo(accountInterventionStatus));

        verify(metrics)
                .incrementCounter(
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

        verify(auditService).submitAuditEvent(eq(AIS_RESPONSE_RECEIVED), any());
    }

    public static class PactGenerator {

        public static RequestResponsePact successfulResponse(
                PactDslWithProvider builder,
                boolean blocked,
                boolean suspended,
                boolean reproveIdentity,
                boolean resetPassword) {
            return builder.given(
                            String.format(
                                    "internal pairwise subject id corresponds to an account that has state: blocked = %s, suspended = %s, reproveIdentity = %s, resetPassword = %s",
                                    blocked, suspended, reproveIdentity, resetPassword))
                    .uponReceiving("a request with a valid internal pairwise subject id")
                    .path("/v1/ais/" + INTERNAL_PAIRWISE_SUBJECT_ID)
                    .method("GET")
                    .willRespondWith()
                    .status(200)
                    .body(createAisResponseBody(blocked, suspended, reproveIdentity, resetPassword))
                    .toPact();
        }
    }
}
