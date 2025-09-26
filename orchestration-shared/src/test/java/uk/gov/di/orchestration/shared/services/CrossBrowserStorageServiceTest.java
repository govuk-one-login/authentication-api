package uk.gov.di.orchestration.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.enhanced.dynamodb.model.GetItemEnhancedRequest;
import uk.gov.di.orchestration.shared.entity.CrossBrowserItem;
import uk.gov.di.orchestration.shared.exceptions.CrossBrowserStorageException;
import uk.gov.di.orchestration.sharedtest.basetest.BaseDynamoServiceTest;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.helper.Constants.CLIENT_SESSION_ID;
import static uk.gov.di.orchestration.sharedtest.helper.Constants.STATE;

class CrossBrowserStorageServiceTest extends BaseDynamoServiceTest<CrossBrowserItem> {
    private static final GetItemEnhancedRequest GET_CROSS_BROWSER_REQUEST =
            getRequestFor(STATE.getValue());
    private static final long SESSION_EXPIRY = 30L;
    private static final Instant CURRENT_TIME = Instant.parse("2025-11-22T15:05:00Z");
    private static final long VALID_TTL =
            CURRENT_TIME.plus(SESSION_EXPIRY, ChronoUnit.SECONDS).getEpochSecond();
    private static final long EXPIRED_TTL =
            CURRENT_TIME.minus(SESSION_EXPIRY, ChronoUnit.SECONDS).getEpochSecond();
    private static final CrossBrowserItem CROSS_BROWSER_ITEM =
            new CrossBrowserItem(STATE, CLIENT_SESSION_ID);
    private CrossBrowserStorageService crossBrowserStorageService;

    @BeforeEach
    void setup() {
        when(configurationService.getSessionExpiry()).thenReturn(SESSION_EXPIRY);
        crossBrowserStorageService =
                new CrossBrowserStorageService(
                        dynamoDbClient,
                        table,
                        configurationService,
                        Clock.fixed(CURRENT_TIME, ZoneId.of("UTC")));
    }

    @Test
    void shouldStoreCrossBrowserItem() {
        crossBrowserStorageService.storeItem(CROSS_BROWSER_ITEM);

        verify(table).putItem(CROSS_BROWSER_ITEM.withTimeToLive(VALID_TTL));
    }

    @Test
    void shouldThrowExceptionWhenFailingToStoreItem() {
        withFailedPut();

        assertThrows(
                CrossBrowserStorageException.class,
                () -> crossBrowserStorageService.storeItem(CROSS_BROWSER_ITEM));
    }

    @Test
    void shouldGetClientSessionIdFromState() {
        withValidGet(CROSS_BROWSER_ITEM.withTimeToLive(VALID_TTL));

        var actualClientSessionId =
                crossBrowserStorageService.getClientSessionId(STATE).orElseThrow();

        assertEquals(CLIENT_SESSION_ID, actualClientSessionId);
    }

    @Test
    void shouldThrowExceptionWhenFailingToGetCrossBrowserItem() {
        withFailedGet();

        assertThrows(
                CrossBrowserStorageException.class,
                () -> crossBrowserStorageService.getClientSessionId(STATE));
    }

    @Test
    void shouldGetNoClientSessionIdWhenNoCrossBrowserItemExists() {
        var actualClientSessionIdOpt = crossBrowserStorageService.getClientSessionId(STATE);
        assertFalse(actualClientSessionIdOpt.isPresent());
    }

    @Test
    void shouldGetNoClientSessionIdWhenCrossBrowserItemHasExpired() {
        withValidGet(CROSS_BROWSER_ITEM.withTimeToLive(EXPIRED_TTL));

        var actualClientSessionIdOpt = crossBrowserStorageService.getClientSessionId(STATE);
        assertFalse(actualClientSessionIdOpt.isPresent());
    }

    private void withValidGet(CrossBrowserItem crossBrowserItem) {
        when(table.getItem(GET_CROSS_BROWSER_REQUEST)).thenReturn(crossBrowserItem);
    }
}
