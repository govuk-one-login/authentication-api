package uk.gov.di.orchestration.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.enhanced.dynamodb.model.GetItemEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import uk.gov.di.orchestration.shared.entity.OrchAccessTokenItem;
import uk.gov.di.orchestration.shared.exceptions.OrchAccessTokenException;
import uk.gov.di.orchestration.sharedtest.basetest.BaseDynamoServiceTest;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OrchAccessTokenServiceTest extends BaseDynamoServiceTest<OrchAccessTokenItem> {

    private static final String CLIENT_AND_RP_PAIRWISE_ID = "test-clientId.rpPairwiseId";
    private static final String TOKEN = "test-token";
    private static final String INTERNAL_PAIRWISE_SUBJECT_ID = "test-internal-pairwise-subject-id";
    private static final String CLIENT_SESSION_ID = "test-client-session-id";
    private static final String AUTH_CODE = "test-auth-code";
    private static final String AUTH_CODE_INDEX = "AuthCodeIndex";
    private static final Instant CREATION_INSTANT = Instant.parse("2025-02-01T03:04:05.678Z");

    private final BaseDynamoService<OrchAccessTokenItem> mockOldService =
            mock(BaseDynamoService.class);
    private final BaseDynamoService<OrchAccessTokenItem> mockNewService =
            mock(BaseDynamoService.class);
    private OrchAccessTokenService orchAccessTokenService;

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(OrchAccessTokenService.class);

    @BeforeEach
    void setup() {
        when(configurationService.getAccessTokenExpiry()).thenReturn(3600L);
        orchAccessTokenService =
                new OrchAccessTokenService(
                        mockOldService,
                        mockNewService,
                        configurationService,
                        Clock.fixed(CREATION_INSTANT, ZoneId.systemDefault()));
    }

    @Nested
    class StoreOrchAccessToken {
        @Test
        void shouldStoreAccessTokenSuccessfully() {
            doNothing().when(mockOldService).put(any(OrchAccessTokenItem.class));
            doNothing().when(mockNewService).put(any(OrchAccessTokenItem.class));

            orchAccessTokenService.saveAccessToken(
                    CLIENT_AND_RP_PAIRWISE_ID,
                    AUTH_CODE,
                    TOKEN,
                    INTERNAL_PAIRWISE_SUBJECT_ID,
                    CLIENT_SESSION_ID);

            var oldServiceCaptor = ArgumentCaptor.forClass(OrchAccessTokenItem.class);
            var newServiceCaptor = ArgumentCaptor.forClass(OrchAccessTokenItem.class);

            verify(mockOldService).put(oldServiceCaptor.capture());
            verify(mockNewService).put(newServiceCaptor.capture());

            var capturedRequest = oldServiceCaptor.getValue();
            assertOrchAccessTokenItemMatchesExpected(capturedRequest);
            assertTrue(capturedRequest.getTimeToLive() > CREATION_INSTANT.getEpochSecond());
            assertEquals(oldServiceCaptor.getValue(), newServiceCaptor.getValue());
        }

        @Test
        void shouldThrowWhenDynamoThrowsException() {
            doThrow(DynamoDbException.builder().message("Failed to put item in table").build())
                    .when(mockOldService)
                    .put(any(OrchAccessTokenItem.class));

            var exception =
                    assertThrows(
                            OrchAccessTokenException.class,
                            () ->
                                    orchAccessTokenService.saveAccessToken(
                                            CLIENT_AND_RP_PAIRWISE_ID,
                                            TOKEN,
                                            INTERNAL_PAIRWISE_SUBJECT_ID,
                                            CLIENT_SESSION_ID,
                                            AUTH_CODE));
            assertEquals("Failed to save Orch access token item to Dynamo", exception.getMessage());
        }
    }

    @Nested
    class GetOrchAccessTokenByClientAndRpPairwiseIdAndAuthCode {
        @Test
        void shouldGetAccessTokenSuccessfully() {
            var orchAccessTokenItem =
                    new OrchAccessTokenItem()
                            .withClientAndRpPairwiseId(CLIENT_AND_RP_PAIRWISE_ID)
                            .withToken(TOKEN)
                            .withInternalPairwiseSubjectId(INTERNAL_PAIRWISE_SUBJECT_ID)
                            .withClientSessionId(CLIENT_SESSION_ID)
                            .withAuthCode(AUTH_CODE);

            when(mockNewService.get(CLIENT_AND_RP_PAIRWISE_ID, AUTH_CODE))
                    .thenReturn(Optional.of(orchAccessTokenItem));

            var actualOrchAccessToken =
                    orchAccessTokenService.getAccessToken(CLIENT_AND_RP_PAIRWISE_ID, AUTH_CODE);

            assertTrue(actualOrchAccessToken.isPresent());
            assertOrchAccessTokenItemMatchesExpected(actualOrchAccessToken.get());
        }

        @Test
        void shouldReturnEmptyWhenNoAccessTokenForClientIdAndRpPairwiseId() {
            when(table.getItem(any(GetItemEnhancedRequest.class))).thenReturn(null);

            var actualOrchAccessToken =
                    orchAccessTokenService.getAccessToken(CLIENT_AND_RP_PAIRWISE_ID, AUTH_CODE);

            assertTrue(actualOrchAccessToken.isEmpty());
        }

        @Test
        void shouldThrowWhenDynamoThrowsException() {
            when(mockNewService.get(CLIENT_AND_RP_PAIRWISE_ID, AUTH_CODE))
                    .thenThrow(DynamoDbException.class);

            var exception =
                    assertThrows(
                            OrchAccessTokenException.class,
                            () ->
                                    orchAccessTokenService.getAccessToken(
                                            CLIENT_AND_RP_PAIRWISE_ID, AUTH_CODE));
            assertEquals("Failed to get Orch access token from Dynamo", exception.getMessage());
        }
    }

    @Nested
    class GetOrchAccessTokenByAuthCode {
        @Test
        void shouldGetAccessTokenSuccessfully() {
            var orchAccessTokenItem =
                    new OrchAccessTokenItem()
                            .withClientAndRpPairwiseId(CLIENT_AND_RP_PAIRWISE_ID)
                            .withAuthCode(AUTH_CODE)
                            .withToken(TOKEN)
                            .withInternalPairwiseSubjectId(INTERNAL_PAIRWISE_SUBJECT_ID)
                            .withClientSessionId(CLIENT_SESSION_ID);

            when(mockNewService.queryIndex(AUTH_CODE_INDEX, AUTH_CODE))
                    .thenReturn(List.of(orchAccessTokenItem));

            var actualOrchAccessToken = orchAccessTokenService.getAccessTokenForAuthCode(AUTH_CODE);

            assertTrue(actualOrchAccessToken.isPresent());
            assertOrchAccessTokenItemMatchesExpected(actualOrchAccessToken.get());
        }

        @Test
        void shouldReturnEmptyWhenNoAccessTokenForAuthCode() {
            when(mockNewService.queryIndex(AUTH_CODE_INDEX, AUTH_CODE)).thenReturn(List.of());

            var actualOrchAccessToken = orchAccessTokenService.getAccessTokenForAuthCode(AUTH_CODE);

            assertTrue(actualOrchAccessToken.isEmpty());
        }

        @Test
        void shouldThrowWhenDynamoThrowsException() {
            when(mockNewService.queryIndex(AUTH_CODE_INDEX, AUTH_CODE))
                    .thenThrow(DynamoDbException.class);

            var exception =
                    assertThrows(
                            OrchAccessTokenException.class,
                            () -> orchAccessTokenService.getAccessTokenForAuthCode(AUTH_CODE));
            assertEquals("Failed to get Orch access token from Dynamo", exception.getMessage());
        }
    }

    @Nested
    class GetOrchAccessTokenByClientAndRpPairwiseIdAndTokenValue {
        @Test
        void shouldGetAccessTokenSuccessfully() {
            var orchAccessTokenItem =
                    new OrchAccessTokenItem()
                            .withClientAndRpPairwiseId(CLIENT_AND_RP_PAIRWISE_ID)
                            .withAuthCode(AUTH_CODE)
                            .withToken(TOKEN)
                            .withInternalPairwiseSubjectId(INTERNAL_PAIRWISE_SUBJECT_ID)
                            .withClientSessionId(CLIENT_SESSION_ID);

            when(mockNewService.queryTableStream(CLIENT_AND_RP_PAIRWISE_ID))
                    .thenReturn(Stream.of(orchAccessTokenItem));

            var actualOrchAccessToken =
                    orchAccessTokenService.getAccessTokenForClientAndRpPairwiseIdAndTokenValue(
                            CLIENT_AND_RP_PAIRWISE_ID, TOKEN);

            assertTrue(actualOrchAccessToken.isPresent());
            assertOrchAccessTokenItemMatchesExpected(actualOrchAccessToken.get());
        }

        @Test
        void shouldReturnEmptyWhenNoMatchForTokenValue() {
            var orchAccessTokenItem =
                    new OrchAccessTokenItem()
                            .withClientAndRpPairwiseId(CLIENT_AND_RP_PAIRWISE_ID)
                            .withAuthCode(AUTH_CODE)
                            .withToken("different-token-value")
                            .withInternalPairwiseSubjectId(INTERNAL_PAIRWISE_SUBJECT_ID)
                            .withClientSessionId(CLIENT_SESSION_ID);

            when(mockNewService.queryTableStream(CLIENT_AND_RP_PAIRWISE_ID))
                    .thenReturn(Stream.of(orchAccessTokenItem));

            var actualOrchAccessToken =
                    orchAccessTokenService.getAccessTokenForClientAndRpPairwiseIdAndTokenValue(
                            CLIENT_AND_RP_PAIRWISE_ID, TOKEN);

            assertTrue(actualOrchAccessToken.isEmpty());
        }

        @Test
        void shouldThrowWhenDynamoThrowsException() {
            when(mockNewService.queryTableStream(CLIENT_AND_RP_PAIRWISE_ID))
                    .thenThrow(DynamoDbException.class);

            var exception =
                    assertThrows(
                            OrchAccessTokenException.class,
                            () ->
                                    orchAccessTokenService
                                            .getAccessTokenForClientAndRpPairwiseIdAndTokenValue(
                                                    CLIENT_AND_RP_PAIRWISE_ID, TOKEN));
            assertEquals("Failed to get Orch access token from Dynamo", exception.getMessage());
        }
    }

    private void assertOrchAccessTokenItemMatchesExpected(OrchAccessTokenItem orchAccessTokenItem) {
        assertEquals(CLIENT_AND_RP_PAIRWISE_ID, orchAccessTokenItem.getClientAndRpPairwiseId());
        assertEquals(TOKEN, orchAccessTokenItem.getToken());
        assertEquals(
                INTERNAL_PAIRWISE_SUBJECT_ID, orchAccessTokenItem.getInternalPairwiseSubjectId());
        assertEquals(CLIENT_SESSION_ID, orchAccessTokenItem.getClientSessionId());
        assertEquals(AUTH_CODE, orchAccessTokenItem.getAuthCode());
    }
}
