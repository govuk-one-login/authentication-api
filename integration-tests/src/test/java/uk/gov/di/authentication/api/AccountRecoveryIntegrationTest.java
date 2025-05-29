package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.frontendapi.entity.AccountRecoveryResponse;
import uk.gov.di.authentication.frontendapi.lambda.AccountRecoveryHandler;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AuthSessionExtension;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_ACCOUNT_RECOVERY_NOT_PERMITTED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_ACCOUNT_RECOVERY_PERMITTED;
import static uk.gov.di.authentication.shared.helpers.TxmaAuditHelper.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class AccountRecoveryIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    public static final String CLIENT_SESSION_ID = "some-client-session-id";
    private static final String INTERNAl_SECTOR_URI = "https://test.account.gov.uk";
    private static final String INTERNAl_SECTOR_HOST = "test.account.gov.uk";
    private static final Subject SUBJECT = new Subject();
    public static final String ENCODED_DEVICE_DETAILS =
            "YTtKVSlub1YlOSBTeEI4J3pVLVd7Jjl8VkBfREs2N3clZmN+fnU7fXNbcTJjKyEzN2IuUXIgMGttV058fGhUZ0xhenZUdldEblB8SH18XypwXUhWPXhYXTNQeURW%";

    @RegisterExtension
    public static final AuthSessionExtension authSessionServiceExtension =
            new AuthSessionExtension();

    @BeforeEach
    void setup() {
        handler =
                new AccountRecoveryHandler(
                        new AccountRecoveryTestConfigurationService(), redisConnectionService);
        txmaAuditQueue.clear();
    }

    @Test
    void shouldNotBePermittedForAccountRecoveryWhenBlockIsPresent() throws Json.JsonException {
        userStore.signUp(EMAIL, "password-1", SUBJECT);
        var salt = userStore.addSalt(EMAIL);
        var internalCommonSubjectId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAl_SECTOR_HOST, salt);
        var sessionId = redis.createSession();
        authSessionServiceExtension.addSession(sessionId);
        accountModifiersStore.setAccountRecoveryBlock(internalCommonSubjectId);
        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS);
        var response =
                makeRequest(Optional.of(format("{ \"email\": \"%s\"}", EMAIL)), headers, Map.of());

        assertThat(response, hasStatus(200));
        assertThat(response, hasJsonBody(new AccountRecoveryResponse(false)));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_ACCOUNT_RECOVERY_NOT_PERMITTED));
    }

    @Test
    void shouldBePermittedForAccountRecoveryWhenNoBlockIsPresent() throws Json.JsonException {
        var sessionId = redis.createSession();
        authSessionServiceExtension.addSession(sessionId);
        userStore.signUp(EMAIL, "password-1", SUBJECT);

        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS);
        var response =
                makeRequest(Optional.of(format("{ \"email\": \"%s\"}", EMAIL)), headers, Map.of());

        assertThat(response, hasStatus(200));
        assertThat(response, hasJsonBody(new AccountRecoveryResponse(true)));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_ACCOUNT_RECOVERY_PERMITTED));
    }

    private static class AccountRecoveryTestConfigurationService
            extends IntegrationTestConfigurationService {

        public AccountRecoveryTestConfigurationService() {
            super(
                    notificationsQueue,
                    tokenSigner,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters);
        }

        @Override
        public String getInternalSectorUri() {
            return INTERNAl_SECTOR_URI;
        }

        @Override
        public String getTxmaAuditQueueUrl() {
            return txmaAuditQueue.getQueueUrl();
        }
    }
}
