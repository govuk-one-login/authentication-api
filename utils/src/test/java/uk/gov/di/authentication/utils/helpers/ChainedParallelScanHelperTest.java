package uk.gov.di.authentication.utils.helpers;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ForkJoinPool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ChainedParallelScanHelperTest {

    @Test
    void toDynamoKeysShouldReturnNullForNullInput() {
        assertNull(ChainedParallelScanHelper.toDynamoKeys(null));
    }

    @Test
    void toDynamoKeysShouldReturnNullForEmptyMap() {
        assertNull(ChainedParallelScanHelper.toDynamoKeys(Map.of()));
    }

    @Test
    void toDynamoKeysShouldConvertSingleEntry() {
        var result = ChainedParallelScanHelper.toDynamoKeys(Map.of("Email", "user@example.com"));

        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals("user@example.com", result.get("Email").s());
    }

    @Test
    void toDynamoKeysShouldConvertMultipleEntries() {
        Map<String, String> input = new HashMap<>();
        input.put("Email", "user@example.com");
        input.put("SubjectID", "subject-123");

        var result = ChainedParallelScanHelper.toDynamoKeys(input);

        assertNotNull(result);
        assertEquals(2, result.size());
        assertEquals("user@example.com", result.get("Email").s());
        assertEquals("subject-123", result.get("SubjectID").s());
    }

    @Test
    void toSerialisableKeysShouldConvertEmptyMap() {
        var result = ChainedParallelScanHelper.toSerialisableKeys(Map.of());

        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void toSerialisableKeysShouldConvertSingleEntry() {
        var input = Map.of("Email", AttributeValue.builder().s("user@example.com").build());

        var result = ChainedParallelScanHelper.toSerialisableKeys(input);

        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals("user@example.com", result.get("Email"));
    }

    @Test
    void toSerialisableKeysShouldConvertMultipleEntries() {
        Map<String, AttributeValue> input = new HashMap<>();
        input.put("Email", AttributeValue.builder().s("user@example.com").build());
        input.put("SubjectID", AttributeValue.builder().s("subject-123").build());

        var result = ChainedParallelScanHelper.toSerialisableKeys(input);

        assertNotNull(result);
        assertEquals(2, result.size());
        assertEquals("user@example.com", result.get("Email"));
        assertEquals("subject-123", result.get("SubjectID"));
    }

    @Test
    void toDynamoKeysAndToSerialisableKeysShouldRoundTrip() {
        Map<String, String> original = new HashMap<>();
        original.put("Email", "user@example.com");
        original.put("PK", "abc-123");

        var dynamo = ChainedParallelScanHelper.toDynamoKeys(original);
        var roundTripped = ChainedParallelScanHelper.toSerialisableKeys(dynamo);

        assertEquals(original, roundTripped);
    }

    @Test
    void gracefulPoolShutdownShouldTerminatePool() {
        ForkJoinPool pool = new ForkJoinPool(1);

        ChainedParallelScanHelper.gracefulPoolShutdown(pool);

        assertTrue(pool.isShutdown());
        assertTrue(pool.isTerminated());
    }

    @Test
    void forcePoolShutdownShouldShutDownRunningPool() {
        ForkJoinPool pool = new ForkJoinPool(1);

        ChainedParallelScanHelper.forcePoolShutdown(pool);

        assertTrue(pool.isShutdown());
    }

    @Test
    void forcePoolShutdownShouldBeIdempotentOnAlreadyShutdownPool() {
        ForkJoinPool pool = new ForkJoinPool(1);
        pool.shutdown();

        ChainedParallelScanHelper.forcePoolShutdown(pool);

        assertTrue(pool.isShutdown());
    }
}
