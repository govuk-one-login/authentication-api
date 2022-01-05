package uk.gov.di.authentication.shared.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class ClientSessionServiceTest {

    private final RedisConnectionService redis = mock(RedisConnectionService.class);
    private final ConfigurationService configuration = mock(ConfigurationService.class);
    private final ObjectMapper objectMapper =
            JsonMapper.builder().addModule(new JavaTimeModule()).build();

    private final ClientSessionService clientSessionService =
            new ClientSessionService(configuration, redis);

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(ClientSessionService.class);

    private final String clientSessionId = IdGenerator.generate();
    private final String sessionId = IdGenerator.generate();

    @AfterEach
    public void tearDown() {
        assertThat(
                logging.events(), not(hasItem(withMessageContaining(clientSessionId, sessionId))));
    }

    @Test
    void shouldRetrieveClientSessionUsingRequestHeaders() throws JsonProcessingException {
        when(redis.getValue("client-session-" + clientSessionId))
                .thenReturn(generateSerialisedClientSession());

        Optional<ClientSession> clientSessionInRedis =
                clientSessionService.getClientSessionFromRequestHeaders(
                        Map.of("Session-Id", sessionId, "Client-Session-Id", clientSessionId));

        clientSessionInRedis.ifPresentOrElse(
                clientSession ->
                        assertThat(
                                clientSession.getAuthRequestParams().containsKey("authparam"),
                                is(true)),
                () -> fail("Could not retrieve client session"));
    }

    @Test
    void shouldNotRetrieveClientSessionUsingNullRequestHeaders() throws JsonProcessingException {
        when(redis.getValue(clientSessionId)).thenReturn(generateSerialisedClientSession());

        Optional<ClientSession> clientSessionInRedis =
                clientSessionService.getClientSessionFromRequestHeaders(null);

        assertTrue(clientSessionInRedis.isEmpty());
    }

    @Test
    void shouldNotRetrieveClientSessionForLowerCaseHeaderName() throws JsonProcessingException {
        when(redis.getValue(clientSessionId)).thenReturn(generateSerialisedClientSession());

        Optional<ClientSession> clientSessionInRedis =
                clientSessionService.getClientSessionFromRequestHeaders(
                        Map.of("Session-Id", sessionId, "client-Session-id", clientSessionId));

        assertTrue(clientSessionInRedis.isEmpty());
    }

    @Test
    void shouldNotRetrieveClientSessionWithNoHeaders() throws JsonProcessingException {
        when(redis.getValue(clientSessionId)).thenReturn(generateSerialisedClientSession());

        Optional<ClientSession> clientSessionInRedis =
                clientSessionService.getClientSessionFromRequestHeaders(Collections.emptyMap());

        assertTrue(clientSessionInRedis.isEmpty());
    }

    @Test
    void shouldNotRetrieveClientSessionWithMissingHeader() throws JsonProcessingException {
        when(redis.getValue(clientSessionId)).thenReturn(generateSerialisedClientSession());

        Optional<ClientSession> clientSessionInRedis =
                clientSessionService.getClientSessionFromRequestHeaders(
                        Map.of("Something", "Else"));

        assertTrue(clientSessionInRedis.isEmpty());
    }

    @Test
    void shouldNotRetrieveClientSessionAndThrowExceptionIfNotPresentInRedis() {
        final Map headers = Map.of("Session-Id", sessionId, "Client-Session-Id", clientSessionId);

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> clientSessionService.getClientSessionFromRequestHeaders(headers),
                        "Expected to throw exception");

        assertTrue(
                exception
                        .getMessage()
                        .contains(
                                "java.lang.IllegalArgumentException: argument \"content\" is null"));
    }

    private String generateSerialisedClientSession() throws JsonProcessingException {
        return objectMapper.writeValueAsString(
                new ClientSession(
                        Map.of("authparam", List.of("v1", "v2")),
                        LocalDateTime.now(),
                        VectorOfTrust.getDefaults()));
    }
}
