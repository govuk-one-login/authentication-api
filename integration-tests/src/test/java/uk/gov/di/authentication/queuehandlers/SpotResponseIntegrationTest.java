package uk.gov.di.authentication.queuehandlers;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.lambda.SPOTResponseHandler;
import uk.gov.di.orchestration.shared.entity.IdentityCredentials;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.sharedtest.basetest.IntegrationTest;

import java.util.Arrays;
import java.util.Collections;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

import static java.lang.String.format;
import static java.util.Collections.emptyMap;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static uk.gov.di.orchestration.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.orchestration.sharedtest.helper.IdentityTestData.ADDRESS_CLAIM;
import static uk.gov.di.orchestration.sharedtest.helper.IdentityTestData.CORE_IDENTITY_CLAIM;
import static uk.gov.di.orchestration.sharedtest.helper.IdentityTestData.PASSPORT_CLAIM;

public class SpotResponseIntegrationTest extends IntegrationTest {

    private static final String SESSION_ID = "a-session-id";
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final String PERSISTENT_SESSION_ID = "a-persistent-id";
    private static final ClientID CLIENT_ID = new ClientID();
    private static final String REQUEST_ID = "request-id";

    private RequestHandler<SQSEvent, Object> handler;

    @BeforeEach
    void setup() {
        handler = new SPOTResponseHandler(TXMA_ENABLED_CONFIGURATION_SERVICE);
        txmaAuditQueue.clear();
    }

    @Test
    void shouldAddSpotCredentialToDBForValidResponseWhenEntryAlreadyExists() {
        var pairwiseIdentifier = new Subject();
        identityStore.saveIdentityClaims(
                pairwiseIdentifier.getValue(),
                Map.of(
                        ValidClaims.ADDRESS.getValue(),
                        ADDRESS_CLAIM,
                        ValidClaims.PASSPORT.getValue(),
                        PASSPORT_CLAIM),
                LevelOfConfidence.MEDIUM_LEVEL.toString(),
                CORE_IDENTITY_CLAIM);
        var signedCredential = "some-signed-credential";
        var spotResponse =
                format(
                        "{\"sub\":\"%s\",\"status\":\"ACCEPTED\","
                                + "\"claims\":{\"http://something/v1/verifiableIdentityJWT\":\"%s\"}, \"log_ids\":{\"session_id\":\"%s\",\"client_session_id\":\"%s\",\"persistent_session_id\":\"%s\",\"request_id\":\"%s\",\"client_id\":\"%s\"}}",
                        pairwiseIdentifier,
                        signedCredential,
                        SESSION_ID,
                        CLIENT_SESSION_ID,
                        PERSISTENT_SESSION_ID,
                        REQUEST_ID,
                        CLIENT_ID);
        handler.handleRequest(createSqsEvent(spotResponse), mock(Context.class));

        Optional<IdentityCredentials> identityCredentials =
                identityStore.getIdentityCredentials(pairwiseIdentifier.getValue());
        assertTrue(identityCredentials.isPresent());
        assertThat(
                identityCredentials.get().getIpvVot(),
                equalTo(LevelOfConfidence.MEDIUM_LEVEL.toString()));
        assertThat(identityCredentials.get().getAdditionalClaims().size(), equalTo(2));
        assertThat(identityCredentials.get().getIpvCoreIdentity(), equalTo(CORE_IDENTITY_CLAIM));
        assertThat(identityCredentials.get().getCoreIdentityJWT(), equalTo(signedCredential));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                Collections.singletonList(IPVAuditableEvent.IPV_SUCCESSFUL_SPOT_RESPONSE_RECEIVED));
    }

    @Test
    void shouldAddSpotCredentialToDBForValidResponseWhenNoEntryCurrentlyExists() {
        var pairwiseIdentifier = new Subject();
        var signedCredential = "some-signed-credential";
        var spotResponse =
                format(
                        "{\"sub\":\"%s\",\"status\":\"ACCEPTED\","
                                + "\"claims\":{\"http://something/v1/verifiableIdentityJWT\":\"%s\"}, \"log_ids\":{\"session_id\":\"%s\",\"client_session_id\":\"%s\",\"persistent_session_id\":\"%s\",\"request_id\":\"%s\",\"client_id\":\"%s\"}}",
                        pairwiseIdentifier,
                        signedCredential,
                        SESSION_ID,
                        CLIENT_SESSION_ID,
                        PERSISTENT_SESSION_ID,
                        REQUEST_ID,
                        CLIENT_ID);
        handler.handleRequest(createSqsEvent(spotResponse), mock(Context.class));

        Optional<IdentityCredentials> identityCredentials =
                identityStore.getIdentityCredentials(pairwiseIdentifier.getValue());
        assertTrue(identityCredentials.isPresent());
        assertNull(identityCredentials.get().getAdditionalClaims());
        assertNull(identityCredentials.get().getIpvVot());
        assertNull(identityCredentials.get().getIpvCoreIdentity());

        assertThat(identityCredentials.get().getCoreIdentityJWT(), equalTo(signedCredential));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                Collections.singletonList(IPVAuditableEvent.IPV_SUCCESSFUL_SPOT_RESPONSE_RECEIVED));
    }

    @Test
    void shouldDeleteIdentityCredentialFromDBForInvalidResponse() {
        var pairwiseIdentifier = new Subject();
        var spotResponse =
                format(
                        "{\"sub\":\"%s\",\"status\":\"REJECTED\","
                                + "\"log_ids\":{\"session_id\":\"%s\",\"client_session_id\":\"%s\",\"persistent_session_id\":\"%s\",\"request_id\":\"%s\",\"client_id\":\"%s\"}}",
                        pairwiseIdentifier,
                        SESSION_ID,
                        CLIENT_SESSION_ID,
                        PERSISTENT_SESSION_ID,
                        REQUEST_ID,
                        CLIENT_ID);
        identityStore.saveIdentityClaims(
                pairwiseIdentifier.getValue(),
                emptyMap(),
                LevelOfConfidence.MEDIUM_LEVEL.toString(),
                CORE_IDENTITY_CLAIM);
        handler.handleRequest(createSqsEvent(spotResponse), mock(Context.class));

        assertFalse(
                identityStore.getIdentityCredentials(pairwiseIdentifier.getValue()).isPresent());
        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                Collections.singletonList(
                        IPVAuditableEvent.IPV_UNSUCCESSFUL_SPOT_RESPONSE_RECEIVED));
    }

    private <T> SQSEvent createSqsEvent(T... request) {
        var event = new SQSEvent();
        event.setRecords(
                Arrays.stream(request)
                        .map(
                                r -> {
                                    var message = new SQSEvent.SQSMessage();
                                    message.setBody((String) r);
                                    message.setMessageId(UUID.randomUUID().toString());
                                    message.setMd5OfBody(
                                            DigestUtils.md5Hex(message.getBody())
                                                    .toUpperCase(Locale.ROOT));
                                    message.setEventSource("aws:sqs");
                                    message.setAwsRegion("eu-west-2");
                                    message.setEventSourceArn(
                                            "arn:aws:sqs:eu-west-2:123456789012:queue-name");
                                    return message;
                                })
                        .collect(Collectors.toList()));
        return event;
    }
}
