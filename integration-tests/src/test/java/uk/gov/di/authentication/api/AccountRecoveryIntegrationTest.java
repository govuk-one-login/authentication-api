package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.AccountRecoveryResponse;
import uk.gov.di.authentication.frontendapi.lambda.AccountRecoveryHandler;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.ACCOUNT_RECOVERY_NOT_PERMITTED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.ACCOUNT_RECOVERY_PERMITTED;
import static uk.gov.di.authentication.shared.lambda.BaseFrontendHandler.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.*;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class AccountRecoveryIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final Subject SUBJECT = new Subject();

    @BeforeEach
    void setup() {
        handler =
                new AccountRecoveryHandler(
                        new AccountRecoveryTestConfigurationService(), redisConnectionService);
        txmaAuditQueue.clear();
    }

    @Test
    void shouldNotBePermittedForAccountRecoveryWhenBlockIsPresent() throws Json.JsonException {
        userStore.signUp(EMAIL, PASSWORD, SUBJECT);
        var salt = userStore.addSalt(EMAIL);
        var internalCommonSubjectId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAL_SECTOR_HOST, salt);
        var sessionId = redis.createSession();
        accountModifiersStore.setAccountRecoveryBlock(internalCommonSubjectId);
        redis.addEmailToSession(sessionId, EMAIL);
        redis.createClientSession(CLIENT_SESSION_ID, createClientSession());
        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS);
        var response =
                makeRequest(Optional.of(format("{ \"email\": \"%s\"}", EMAIL)), headers, Map.of());

        assertThat(response, hasStatus(200));
        assertThat(response, hasJsonBody(new AccountRecoveryResponse(false)));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(ACCOUNT_RECOVERY_NOT_PERMITTED));
    }

    @Test
    void shouldBePermittedForAccountRecoveryWhenNoBlockIsPresent() throws Json.JsonException {
        var sessionId = redis.createSession();
        userStore.signUp(EMAIL, PASSWORD, SUBJECT);
        redis.addEmailToSession(sessionId, EMAIL);
        redis.createClientSession(CLIENT_SESSION_ID, createClientSession());

        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS);
        var response =
                makeRequest(Optional.of(format("{ \"email\": \"%s\"}", EMAIL)), headers, Map.of());

        assertThat(response, hasStatus(200));
        assertThat(response, hasJsonBody(new AccountRecoveryResponse(true)));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(ACCOUNT_RECOVERY_PERMITTED));
    }

    private ClientSession createClientSession() {
        var authRequestBuilder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                new Scope(OIDCScopeValue.OPENID),
                                new ClientID("test-client-id"),
                                URI.create("http://localhost/redirect"))
                        .state(new State())
                        .nonce(new Nonce());
        return new ClientSession(
                authRequestBuilder.build().toParameters(),
                LocalDateTime.now(),
                VectorOfTrust.getDefaults(),
                "test-client-name");
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
            return INTERNAL_SECTOR_URI;
        }

        @Override
        public String getTxmaAuditQueueUrl() {
            return txmaAuditQueue.getQueueUrl();
        }
    }
}
