package uk.gov.di.accountmanagement.services;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.model.Page;
import software.amazon.awssdk.enhanced.dynamodb.model.PageIterable;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryEnhancedRequest;
import uk.gov.di.accountmanagement.entity.IADCircuitBreakerItem;
import uk.gov.di.authentication.shared.serialization.Json;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("unchecked")
class IADCircuitBreakerServiceTest {

    private static final Instant FIXED_INSTANT = Instant.parse("2026-09-04T14:00:00Z");
    private static final Clock FIXED_CLOCK = Clock.fixed(FIXED_INSTANT, ZoneOffset.UTC);

    private static final String PUBLIC_SUBJECT_ID = "public-subject-id";

    private final DynamoDbTable<IADCircuitBreakerItem> dynamoTable = mock(DynamoDbTable.class);
    private final IADCircuitBreakerService service =
            new IADCircuitBreakerService(dynamoTable, FIXED_CLOCK);

    @Test
    void shouldReturnTrueWhenLatestItemHasEnabledTrue() {
        var item = makeItem(true);
        mockQueryResult(List.of(item));

        assertTrue(service.isCircuitBreakerActive());
    }

    @Test
    void shouldReturnFalseWhenLatestItemHasEnabledFalse() {
        var item = makeItem(false);
        mockQueryResult(List.of(item));

        assertFalse(service.isCircuitBreakerActive());
    }

    @Test
    void shouldReturnFalseWhenNoItemsExist() {
        mockQueryResult(List.of());

        assertFalse(service.isCircuitBreakerActive());
    }

    @Test
    void shouldUseStronglyConsistentRead() {
        mockQueryResult(List.of());
        var captor = ArgumentCaptor.forClass(QueryEnhancedRequest.class);

        service.isCircuitBreakerActive();

        verify(dynamoTable).query(captor.capture());
        var request = captor.getValue();
        assertTrue(request.consistentRead());
    }

    @Test
    void shouldQueryWithScanIndexForwardFalseAndLimit1() {
        mockQueryResult(List.of());
        var captor = ArgumentCaptor.forClass(QueryEnhancedRequest.class);

        service.isCircuitBreakerActive();

        verify(dynamoTable).query(captor.capture());
        var request = captor.getValue();
        assertFalse(request.scanIndexForward());
        assertEquals(1, request.limit());
    }

    @Test
    void shouldPutItemWithEnabledTrueWhenTrippingCircuitBreaker() {
        var captor = ArgumentCaptor.forClass(IADCircuitBreakerItem.class);

        service.tripCircuitBreaker("AuthUserActivityCheck", PUBLIC_SUBJECT_ID);

        verify(dynamoTable).putItem(captor.capture());
        var item = captor.getValue();
        assertEquals("IAD", item.getPk());
        assertTrue(item.isEnabled());
    }

    @Test
    void shouldUseDatetimeFromClockWhenTrippingCircuitBreaker() {
        var captor = ArgumentCaptor.forClass(IADCircuitBreakerItem.class);

        service.tripCircuitBreaker("AuthUserActivityCheck", PUBLIC_SUBJECT_ID);

        verify(dynamoTable).putItem(captor.capture());
        assertEquals(FIXED_INSTANT.toEpochMilli(), captor.getValue().getDatetime());
    }

    @Test
    void shouldSerializeMetadataAsJsonWithExpectedFields() {
        var captor = ArgumentCaptor.forClass(IADCircuitBreakerItem.class);

        service.tripCircuitBreaker("AuthUserActivityCheck", PUBLIC_SUBJECT_ID);

        verify(dynamoTable).putItem(captor.capture());
        var metadataJson = captor.getValue().getMetadataJson();
        assertTrue(metadataJson.contains("\"guardrailType\":\"AuthUserActivityCheck\""));
        assertTrue(metadataJson.contains("\"publicSubjectId\":\"" + PUBLIC_SUBJECT_ID + "\""));
    }

    @Test
    void shouldStillWriteItemWhenMetadataSerializationFails() throws Json.JsonException {
        var failingSerializer = mock(Json.class);
        when(failingSerializer.writeValueAsStringCamelCase(any()))
                .thenThrow(new Json.JsonException("serialization error"));
        var serviceWithFailingSerializer =
                new IADCircuitBreakerService(dynamoTable, FIXED_CLOCK, failingSerializer);
        var captor = ArgumentCaptor.forClass(IADCircuitBreakerItem.class);

        serviceWithFailingSerializer.tripCircuitBreaker("AuthUserActivityCheck", PUBLIC_SUBJECT_ID);

        verify(dynamoTable).putItem(captor.capture());
        var item = captor.getValue();
        assertTrue(item.isEnabled());
        assertEquals("IAD", item.getPk());
        assertNull(item.getMetadataJson());
    }

    private IADCircuitBreakerItem makeItem(boolean enabled) {
        var item = new IADCircuitBreakerItem();
        item.setPk("IAD");
        item.setDatetime(1783408027000L);
        item.setEnabled(enabled);
        return item;
    }

    private void mockQueryResult(List<IADCircuitBreakerItem> items) {
        PageIterable<IADCircuitBreakerItem> pageIterable = mock(PageIterable.class);
        doReturn(pageIterable).when(dynamoTable).query(any(QueryEnhancedRequest.class));

        Page<IADCircuitBreakerItem> page = mock(Page.class);
        doReturn(items).when(page).items();
        doReturn(Stream.of(page)).when(pageIterable).stream();
    }
}
