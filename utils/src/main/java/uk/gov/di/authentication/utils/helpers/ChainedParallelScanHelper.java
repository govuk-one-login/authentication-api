package uk.gov.di.authentication.utils.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;

public class ChainedParallelScanHelper {

    private static final Logger LOG = LogManager.getLogger(ChainedParallelScanHelper.class);

    private ChainedParallelScanHelper() {}

    public static Map<String, AttributeValue> toDynamoKeys(Map<String, String> serialisedKey) {
        if (serialisedKey == null || serialisedKey.isEmpty()) {
            return null;
        }
        Map<String, AttributeValue> key = new HashMap<>();
        for (var entry : serialisedKey.entrySet()) {
            key.put(entry.getKey(), AttributeValue.builder().s(entry.getValue()).build());
        }
        return key;
    }

    public static Map<String, String> toSerialisableKeys(Map<String, AttributeValue> key) {
        Map<String, String> serialised = new HashMap<>();
        for (var entry : key.entrySet()) {
            serialised.put(entry.getKey(), entry.getValue().s());
        }
        return serialised;
    }

    public static void gracefulPoolShutdown(ForkJoinPool forkJoinPool) {
        forkJoinPool.shutdown();
        try {
            if (!forkJoinPool.awaitTermination(15, TimeUnit.MINUTES)) {
                LOG.warn("ForkJoinPool did not terminate within 15 minutes");
            }
        } catch (InterruptedException e) {
            LOG.error("ForkJoinPool termination interrupted", e);
            Thread.currentThread().interrupt();
        }
    }

    public static void forcePoolShutdown(ForkJoinPool forkJoinPool) {
        if (!forkJoinPool.isShutdown()) {
            forkJoinPool.shutdownNow();
        }
    }
}
