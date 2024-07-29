package uk.gov.di.authentication.api;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import software.amazon.awssdk.services.lambda.LambdaClient;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.AccountInterventionsResponse;
import uk.gov.di.authentication.frontendapi.lambda.AccountInterventionsHandler;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.LambdaInvokerService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AccountInterventionsStubExtension;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.PERMANENTLY_BLOCKED_INTERVENTION;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.lambda.BaseFrontendHandler.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.*;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class AccountInterventionsHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final String TEST_EMAIL_ADDRESS_PERMANENTLY_BLOCKED_USER =
            buildTestEmail("blocked");
    private static final Subject SUBJECT = new Subject();
    private static final String APPLIED_AT_TIMESTAMP = "1696869005821";

    @RegisterExtension
    public static final AccountInterventionsStubExtension accountInterventionsStubExtension =
            new AccountInterventionsStubExtension();

    protected static final ConfigurationService
            ACCOUNT_INTERVENTIONS_HANDLER_CONFIGURATION_SERVICE =
                    new AccountInterventionsTestConfigurationService(
                            accountInterventionsStubExtension);

    protected static final LambdaClient mockLambdaClient = mock(LambdaClient.class);

    @BeforeEach
    void setup() throws JOSEException, Json.JsonException {
        handler =
                new AccountInterventionsHandler(
                        ACCOUNT_INTERVENTIONS_HANDLER_CONFIGURATION_SERVICE,
                        redisConnectionService,
                        new LambdaInvokerService(mockLambdaClient));
        accountInterventionsStubExtension.initWithBlockedUserId(
                setupUserAndRetrieveUserId(EMAIL),
                setupUserAndRetrieveUserId(TEST_EMAIL_ADDRESS_PERMANENTLY_BLOCKED_USER));
        txmaAuditQueue.clear();
    }

    static Stream<Arguments> accountInterventionResponseParameters() {
        return Stream.of(
                Arguments.of(EMAIL, false, FrontendAuditableEvent.NO_INTERVENTION),
                Arguments.of(
                        TEST_EMAIL_ADDRESS_PERMANENTLY_BLOCKED_USER,
                        true,
                        PERMANENTLY_BLOCKED_INTERVENTION));
    }

    @ParameterizedTest
    @MethodSource("accountInterventionResponseParameters")
    void shouldReturnSuccessful200Response(
            String emailAddress, boolean isUserBlocked, FrontendAuditableEvent expectedAuditEvent)
            throws Json.JsonException {

        var response =
                makeRequest(
                        Optional.of(format("{\"email\":\"%s\"}", emailAddress)),
                        getHeadersForAuthenticatedSession(),
                        Map.of());

        assertThat(response, hasStatus(200));
        var accountInterventionsResponse =
                new AccountInterventionsResponse(
                        false, isUserBlocked, false, false, APPLIED_AT_TIMESTAMP);
        assertThat(
                response,
                hasBody(objectMapper.writeValueAsStringCamelCase(accountInterventionsResponse)));
        assertEquals(
                format(
                        "{\"passwordResetRequired\":false,\"blocked\":%b,\"temporarilySuspended\":false,\"reproveIdentity\":false,\"appliedAt\":\"%s\"}",
                        isUserBlocked, APPLIED_AT_TIMESTAMP),
                response.getBody());
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(expectedAuditEvent));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldReturnSuccessful200ResponseWhenAuthenticatedFieldIsSent(boolean authenticated)
            throws Json.JsonException {
        var body = format("{\"email\":\"%s\",\"authenticated\":%b}", EMAIL, authenticated);
        var response =
                makeRequest(Optional.of(body), getHeadersForAuthenticatedSession(), Map.of());
        assertThat(response, hasStatus(200));
    }

    private Map<String, String> getHeadersForAuthenticatedSession() throws Json.JsonException {
        Map<String, String> headers = new HashMap<>();
        var sessionId = redis.createAuthenticatedSessionWithEmail(EMAIL);

        var clientSession =
                new ClientSession(
                        null,
                        LocalDateTime.now(),
                        new VectorOfTrust(CredentialTrustLevel.LOW_LEVEL),
                        "clientName");

        redis.createClientSession("client-session-id", clientSession);

        headers.put("Session-Id", sessionId);
        headers.put(CLIENT_SESSION_ID_HEADER, "client-session-id");
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS);
        return headers;
    }

    private static class AccountInterventionsTestConfigurationService
            extends IntegrationTestConfigurationService {

        private final AccountInterventionsStubExtension accountInterventionsStubExtension;

        public AccountInterventionsTestConfigurationService(
                AccountInterventionsStubExtension accountInterventionsStubExtension) {
            super(
                    notificationsQueue,
                    tokenSigner,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters);
            this.accountInterventionsStubExtension = accountInterventionsStubExtension;
        }

        @Override
        public URI getAccountInterventionServiceURI() {
            try {
                return new URIBuilder()
                        .setHost("localhost")
                        .setPort(accountInterventionsStubExtension.getHttpPort())
                        .setScheme("http")
                        .build();
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public String getTxmaAuditQueueUrl() {
            return txmaAuditQueue.getQueueUrl();
        }

        @Override
        public boolean accountInterventionsServiceActionEnabled() {
            return true;
        }

        public boolean isAccountInterventionServiceCallEnabled() {
            return true;
        }
    }

    private String setupUserAndRetrieveUserId(String emailAddress) {
        userStore.signUp(emailAddress, PASSWORD, SUBJECT);
        byte[] salt = userStore.addSalt(emailAddress);
        return ClientSubjectHelper.calculatePairwiseIdentifier(
                SUBJECT.getValue(), INTERNAL_SECTOR_HOST, salt);
    }
}
