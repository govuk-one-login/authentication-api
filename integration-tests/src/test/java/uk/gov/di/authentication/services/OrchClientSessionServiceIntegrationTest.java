package uk.gov.di.authentication.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.SubjectType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.OrchClientSessionException;
import uk.gov.di.orchestration.sharedtest.extensions.OrchClientSessionExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;

import static java.time.Clock.fixed;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OrchClientSessionServiceIntegrationTest {
    private static final String CLIENT_SESSION_ID = "test-client-session-id";
    private static final List<VectorOfTrust> VTR_LIST =
            List.of(VectorOfTrust.of(CredentialTrustLevel.LOW_LEVEL, LevelOfConfidence.LOW_LEVEL));
    private final OrchClientSessionItem clientSession =
            new OrchClientSessionItem(CLIENT_SESSION_ID).withVtrList(VTR_LIST);

    @RegisterExtension
    protected static final OrchClientSessionExtension clientSessionExtension =
            new OrchClientSessionExtension();

    @BeforeEach
    void setup() {
        clientSessionExtension.setClock(Clock.systemUTC());
    }

    @Test
    void shouldStoreClientSessionWithAllFieldsSet() {
        var creationInstant = Instant.parse("2025-02-20T14:38:30.547Z");
        var creationDate = LocalDateTime.ofInstant(creationInstant, ZoneId.systemDefault());
        var docAppSubjectId = new Subject("test-doc-app-subject-id");
        var rpPairwiseId = "test-rp-pairwise-id";
        var clientName = "test-client";
        var authRequestParams = Map.of("test-param", List.of("val1", "val2"));
        var idTokenHint = "token-hint";
        var clientSessionWithAllFields =
                new OrchClientSessionItem(
                                CLIENT_SESSION_ID,
                                authRequestParams,
                                creationDate,
                                VTR_LIST,
                                clientName)
                        .withIdTokenHint(idTokenHint)
                        .withRpPairwiseId(rpPairwiseId)
                        .withDocAppSubjectId(docAppSubjectId.getValue());

        // clientSessionService sets TTL when storing a client session
        // If we fix the time we can assert against the TTL
        fixTime(creationInstant);
        clientSessionExtension.storeClientSession(clientSessionWithAllFields);

        var session = clientSessionExtension.getClientSession(CLIENT_SESSION_ID);
        assertTrue(session.isPresent());
        assertThat(session.get().getClientSessionId(), equalTo(CLIENT_SESSION_ID));
        assertThat(session.get().getAuthRequestParams(), equalTo(authRequestParams));
        assertThat(session.get().getIdTokenHint(), equalTo(idTokenHint));
        assertThat(session.get().getCreationDate(), equalTo(creationDate));
        assertThat(session.get().getVtrList(), equalTo(VTR_LIST));
        assertThat(
                session.get().getCorrectPairwiseIdGivenSubjectType(SubjectType.PAIRWISE.toString()),
                equalTo(rpPairwiseId));
        assertThat(session.get().getDocAppSubjectId(), equalTo(docAppSubjectId.getValue()));
        assertThat(session.get().getClientName(), equalTo(clientName));
        // Default expiry is 1 hour (3600 seconds)
        var expectedTimeToLive = creationInstant.plusSeconds(3600).getEpochSecond();
        assertThat(session.get().getTimeToLive(), equalTo(expectedTimeToLive));
    }

    @Test
    void shouldThrowWhenFailingToStoreClientSession() {
        var invalidClientSession = new OrchClientSessionItem(null);
        assertThrows(
                OrchClientSessionException.class,
                () -> clientSessionExtension.storeClientSession(invalidClientSession));
    }

    @Test
    void shouldReturnEmptyOptionalWhenSessionWithIdDoesNotExist() {
        var session = clientSessionExtension.getClientSession("not-a-client-session-id");
        assertTrue(session.isEmpty());
    }

    @Test
    void shouldThrowWhenFailingToGetClientSessionById() {
        assertThrows(
                OrchClientSessionException.class,
                () -> clientSessionExtension.getClientSession(null));
    }

    @Test
    void shouldNotGetClientSessionByIdWhenClientSessionExistsButTimeToLiveExpired() {
        fixTime(Instant.parse("2025-02-18T11:00:00Z"));
        clientSessionExtension.storeClientSession(clientSession);

        // Default expiry is 1 hour (3600 seconds)
        fixTime(Instant.parse("2025-02-18T12:00:01Z"));
        var clientSessionOpt = clientSessionExtension.getClientSession(CLIENT_SESSION_ID);

        assertTrue(clientSessionOpt.isEmpty());
    }

    @Test
    void shouldUpdateTimeToLiveWhenUpdatingClientSession() {
        fixTime(Instant.parse("2025-02-18T11:00:00Z"));
        clientSessionExtension.storeClientSession(clientSession);

        // Reset TTL, so should be valid for another hour
        fixTime(Instant.parse("2025-02-18T11:50:00Z"));
        clientSessionExtension.updateStoredClientSession(clientSession);

        fixTime(Instant.parse("2025-02-18T12:00:01Z"));
        var clientSessionOpt = clientSessionExtension.getClientSession(CLIENT_SESSION_ID);

        assertTrue(clientSessionOpt.isPresent());
    }

    @Test
    void shouldUpdateClientSession() {
        clientSessionExtension.storeClientSession(clientSession);

        clientSession.setClientName("new-client-name");
        clientSessionExtension.updateStoredClientSession(clientSession);

        var actualSession = clientSessionExtension.getClientSession(CLIENT_SESSION_ID);
        assertTrue(actualSession.isPresent());
        assertThat(actualSession.get().getClientName(), equalTo("new-client-name"));
    }

    @Test
    void shouldThrowWhenUpdatingClientSessionFails() {
        var clientSessionWithNoId = new OrchClientSessionItem(null);
        assertThrows(
                OrchClientSessionException.class,
                () -> clientSessionExtension.updateStoredClientSession(clientSessionWithNoId));
    }

    @Test
    void shouldDeleteClientSession() {
        clientSessionExtension.storeClientSession(clientSession);
        var beforeDeletion = clientSessionExtension.getClientSession(CLIENT_SESSION_ID);
        assertTrue(beforeDeletion.isPresent());

        clientSessionExtension.deleteStoredClientSession(CLIENT_SESSION_ID);

        var afterDeletion = clientSessionExtension.getClientSession(CLIENT_SESSION_ID);
        assertTrue(afterDeletion.isEmpty());
    }

    @Test
    void shouldThrowWhenDeletingClientSessionFails() {
        assertThrows(
                OrchClientSessionException.class,
                () -> clientSessionExtension.deleteStoredClientSession(null));
    }

    private static void fixTime(Instant time) {
        clientSessionExtension.setClock(fixed(time, ZoneId.systemDefault()));
    }
}
