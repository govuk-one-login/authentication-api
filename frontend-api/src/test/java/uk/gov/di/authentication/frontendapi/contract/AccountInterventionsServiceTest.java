package uk.gov.di.authentication.frontendapi.contract;

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
import uk.gov.di.authentication.shared.entity.AccountInterventionsInboundResponse;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountInterventionsResponseException;
import uk.gov.di.authentication.shared.services.AccountInterventionsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.net.URI;
import java.net.http.HttpClient;

import static au.com.dius.pact.consumer.dsl.LambdaDsl.newJsonBody;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@PactConsumerTest
@MockServerConfig(hostInterface = "localhost", port = "1234")
public class AccountInterventionsServiceTest {
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final HttpClient httpClient = HttpClient.newHttpClient();
    private AccountInterventionsService accountInterventionsService;

    private static final String PROVIDER_NAME = "AccountInterventionServiceProvider";
    private static final String CONSUMER_NAME = "AuthAccountInterventionServiceConsumer";
    private static final String INTERNAL_PAIRWISE_SUBJECT_ID = "internal-pairwise-subject-id";
    private static final String INVALID_INTERNAL_PAIRWISE_SUBJECT_ID =
            "invalid-internal-pairwise-subject-id";
    private static final Long AIS_CALL_TIMEOUT = 3000L;
    private static final Long TIME_NOW = 1710867479881L;

    @BeforeEach
    void setup() {
        when(configService.getAccountInterventionServiceCallTimeout()).thenReturn(AIS_CALL_TIMEOUT);
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
    void returnsNoInterventionWhenResponseIsNoIntervention(MockServer mockServer)
            throws UnsuccessfulAccountInterventionsResponseException {
        when(configService.getAccountInterventionServiceURI())
                .thenReturn(URI.create(mockServer.getUrl()));
        accountInterventionsService = new AccountInterventionsService(httpClient, configService);

        AccountInterventionsInboundResponse intervention =
                accountInterventionsService.sendAccountInterventionsOutboundRequest(
                        INTERNAL_PAIRWISE_SUBJECT_ID);

        assertFalse(intervention.state().blocked());
        assertFalse(intervention.state().suspended());
        assertFalse(intervention.state().reproveIdentity());
        assertFalse(intervention.state().resetPassword());
        assertEquals(TIME_NOW, intervention.intervention().appliedAt());
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
    void returnsBlockedWhenResponseIsBlocked(MockServer mockServer)
            throws UnsuccessfulAccountInterventionsResponseException {
        when(configService.getAccountInterventionServiceURI())
                .thenReturn(URI.create(mockServer.getUrl()));
        accountInterventionsService = new AccountInterventionsService(httpClient, configService);

        AccountInterventionsInboundResponse intervention =
                accountInterventionsService.sendAccountInterventionsOutboundRequest(
                        INTERNAL_PAIRWISE_SUBJECT_ID);

        assertTrue(intervention.state().blocked());
        assertFalse(intervention.state().suspended());
        assertFalse(intervention.state().reproveIdentity());
        assertFalse(intervention.state().resetPassword());
        assertEquals(TIME_NOW, intervention.intervention().appliedAt());
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
    void returnsSuspendedNoActionWhenResponseIsSuspended(MockServer mockServer)
            throws UnsuccessfulAccountInterventionsResponseException {
        when(configService.getAccountInterventionServiceURI())
                .thenReturn(URI.create(mockServer.getUrl()));
        accountInterventionsService = new AccountInterventionsService(httpClient, configService);

        AccountInterventionsInboundResponse intervention =
                accountInterventionsService.sendAccountInterventionsOutboundRequest(
                        INTERNAL_PAIRWISE_SUBJECT_ID);

        assertFalse(intervention.state().blocked());
        assertTrue(intervention.state().suspended());
        assertFalse(intervention.state().reproveIdentity());
        assertFalse(intervention.state().resetPassword());
        assertEquals(TIME_NOW, intervention.intervention().appliedAt());
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
    void returnsSuspendedReproveIdWhenResponseIsSuspendedReproveIdentity(MockServer mockServer)
            throws UnsuccessfulAccountInterventionsResponseException {
        when(configService.getAccountInterventionServiceURI())
                .thenReturn(URI.create(mockServer.getUrl()));
        accountInterventionsService = new AccountInterventionsService(httpClient, configService);

        AccountInterventionsInboundResponse intervention =
                accountInterventionsService.sendAccountInterventionsOutboundRequest(
                        INTERNAL_PAIRWISE_SUBJECT_ID);

        assertFalse(intervention.state().blocked());
        assertTrue(intervention.state().suspended());
        assertTrue(intervention.state().reproveIdentity());
        assertFalse(intervention.state().resetPassword());
        assertEquals(TIME_NOW, intervention.intervention().appliedAt());
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
    void returnsSuspendedResetPasswordWhenResponseIsSuspendedResetPassword(MockServer mockServer)
            throws UnsuccessfulAccountInterventionsResponseException {
        when(configService.getAccountInterventionServiceURI())
                .thenReturn(URI.create(mockServer.getUrl()));
        accountInterventionsService = new AccountInterventionsService(httpClient, configService);

        AccountInterventionsInboundResponse intervention =
                accountInterventionsService.sendAccountInterventionsOutboundRequest(
                        INTERNAL_PAIRWISE_SUBJECT_ID);

        assertFalse(intervention.state().blocked());
        assertTrue(intervention.state().suspended());
        assertFalse(intervention.state().reproveIdentity());
        assertTrue(intervention.state().resetPassword());
        assertEquals(TIME_NOW, intervention.intervention().appliedAt());
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
            MockServer mockServer) throws UnsuccessfulAccountInterventionsResponseException {
        when(configService.getAccountInterventionServiceURI())
                .thenReturn(URI.create(mockServer.getUrl()));
        accountInterventionsService = new AccountInterventionsService(httpClient, configService);

        AccountInterventionsInboundResponse intervention =
                accountInterventionsService.sendAccountInterventionsOutboundRequest(
                        INTERNAL_PAIRWISE_SUBJECT_ID);

        assertFalse(intervention.state().blocked());
        assertTrue(intervention.state().suspended());
        assertTrue(intervention.state().reproveIdentity());
        assertTrue(intervention.state().resetPassword());
        assertEquals(TIME_NOW, intervention.intervention().appliedAt());
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
    void returnsNoInterventionWhenPairwiseSubjectIdIsInvalid(MockServer mockServer)
            throws UnsuccessfulAccountInterventionsResponseException {
        when(configService.getAccountInterventionServiceURI())
                .thenReturn(URI.create(mockServer.getUrl()));
        accountInterventionsService = new AccountInterventionsService(httpClient, configService);

        AccountInterventionsInboundResponse intervention =
                accountInterventionsService.sendAccountInterventionsOutboundRequest(
                        INVALID_INTERNAL_PAIRWISE_SUBJECT_ID);

        assertFalse(intervention.state().blocked());
        assertFalse(intervention.state().suspended());
        assertFalse(intervention.state().reproveIdentity());
        assertFalse(intervention.state().resetPassword());
        assertEquals(TIME_NOW, intervention.intervention().appliedAt());
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
    void throwsErrorWhenResponseIsServerError500(MockServer mockServer) {
        when(configService.abortOnAccountInterventionsErrorResponse()).thenReturn(true);
        when(configService.getAccountInterventionServiceURI())
                .thenReturn(URI.create(mockServer.getUrl()));
        accountInterventionsService = new AccountInterventionsService(httpClient, configService);

        UnsuccessfulAccountInterventionsResponseException exception =
                assertThrows(
                        UnsuccessfulAccountInterventionsResponseException.class,
                        () ->
                                accountInterventionsService.sendAccountInterventionsOutboundRequest(
                                        INTERNAL_PAIRWISE_SUBJECT_ID));

        assertEquals(500, exception.getHttpCode());
        assertEquals(
                "Error 500 when attempting to call Account Interventions outbound endpoint: ",
                exception.getMessage()); // TODO
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
