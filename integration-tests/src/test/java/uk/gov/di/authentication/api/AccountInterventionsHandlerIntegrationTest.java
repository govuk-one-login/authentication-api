package uk.gov.di.authentication.api;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.AccountInterventionsRequest;
import uk.gov.di.authentication.frontendapi.entity.AccountInterventionsResponse;
import uk.gov.di.authentication.frontendapi.lambda.AccountInterventionsHandler;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AccountInterventionsStubExtension;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.PERMANENTLY_BLOCKED_INTERVENTION;
import static uk.gov.di.authentication.shared.lambda.BaseFrontendHandler.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class AccountInterventionsHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    public static final String CLIENT_SESSION_ID = "some-client-session-id";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_EMAIL_ADDRESS_PERMANENTLY_BLOCKED_USER =
            "blocked.user@blocked.com";
    private static final String TEST_PASSWORD = "password-1";
    private static final String INTERNAl_SECTOR_HOST = "test.account.gov.uk";
    private static final Subject SUBJECT = new Subject();
    private static final String APPLIED_AT_TIMESTAMP = "1696869005821";
    public static final String ENCODED_DEVICE_DETAILS =
            "YTtKVSlub1YlOSBTeEI4J3pVLVd7Jjl8VkBfREs2N3clZmN+fnU7fXNbcTJjKyEzN2IuUXIgMGttV058fGhUZ0xhenZUdldEblB8SH18XypwXUhWPXhYXTNQeURW%";

    @RegisterExtension
    public static final AccountInterventionsStubExtension accountInterventionsStubExtension =
            new AccountInterventionsStubExtension();

    protected static final ConfigurationService
            ACCOUNT_INTERVENTIONS_HANDLER_CONFIGURATION_SERVICE =
                    new AccountInterventionsTestConfigurationService(
                            accountInterventionsStubExtension);

    @BeforeEach
    void setup() throws JOSEException, Json.JsonException {
        handler =
                new AccountInterventionsHandler(
                        ACCOUNT_INTERVENTIONS_HANDLER_CONFIGURATION_SERVICE,
                        redisConnectionService);
        accountInterventionsStubExtension.initWithBlockedUserId(
                setupUserAndRetrieveUserId(TEST_EMAIL_ADDRESS),
                setupUserAndRetrieveUserId(TEST_EMAIL_ADDRESS_PERMANENTLY_BLOCKED_USER));
        txmaAuditQueue.clear();
    }

    static Stream<Arguments> accountInterventionResponseParameters() {
        return Stream.of(
                Arguments.of(TEST_EMAIL_ADDRESS, false, FrontendAuditableEvent.NO_INTERVENTION),
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
                        Optional.of(new AccountInterventionsRequest(emailAddress)),
                        getHeaders(),
                        Map.of());
        assertThat(response, hasStatus(200));
        var accountInterventionsResponse =
                new AccountInterventionsResponse(
                        false, isUserBlocked, false, false, APPLIED_AT_TIMESTAMP);
        assertThat(
                response,
                hasBody(objectMapper.writeValueAsStringCamelCase(accountInterventionsResponse)));
        assertEquals(
                String.format(
                        "{\"passwordResetRequired\":false,\"blocked\":%b,\"temporarilySuspended\":false,\"reproveIdentity\":false,\"appliedAt\":\"%s\"}",
                        isUserBlocked, APPLIED_AT_TIMESTAMP),
                response.getBody());
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(expectedAuditEvent));
    }

    private Map<String, String> getHeaders() throws Json.JsonException {
        Map<String, String> headers = new HashMap<>();
        var sessionId = redis.createSession();
        redis.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        headers.put("Session-Id", sessionId);
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
        userStore.signUp(emailAddress, TEST_PASSWORD, SUBJECT);
        byte[] salt = userStore.addSalt(emailAddress);
        return ClientSubjectHelper.calculatePairwiseIdentifier(
                SUBJECT.getValue(), INTERNAl_SECTOR_HOST, salt);
    }
}
