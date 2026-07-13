package uk.gov.di.authentication.utils.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.KeysAndAttributes;
import uk.gov.di.authentication.shared.entity.UserCredentials;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class InactiveAccountDataExportHelper {

    private static final Logger LOG = LogManager.getLogger(InactiveAccountDataExportHelper.class);
    private static final long BASE_BACKOFF_MS = 100;

    private InactiveAccountDataExportHelper() {}

    public static List<Map<String, AttributeValue>> buildCredentialKeys(
            List<Map<String, AttributeValue>> userProfileItems) {
        List<Map<String, AttributeValue>> keys = new ArrayList<>();

        for (Map<String, AttributeValue> profileItem : userProfileItems) {
            AttributeValue email = profileItem.get(UserCredentials.ATTRIBUTE_EMAIL);
            if (email != null) {
                keys.add(Map.of(UserCredentials.ATTRIBUTE_EMAIL, email));
            }
        }

        return keys;
    }

    public static Map<String, KeysAndAttributes> extractUnprocessedKeys(
            BatchGetItemResponse response, String tableName) {
        Map<String, KeysAndAttributes> unprocessed = response.unprocessedKeys();
        if (unprocessed == null || unprocessed.isEmpty()) {
            return Map.of();
        }

        KeysAndAttributes keysAndAttrs = unprocessed.get(tableName);
        if (keysAndAttrs == null || keysAndAttrs.keys().isEmpty()) {
            return Map.of();
        }

        return new HashMap<>(unprocessed);
    }

    public static void backoff(int retryCount) {
        try {
            Thread.sleep(BASE_BACKOFF_MS * (1L << (retryCount - 1)));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOG.error("Backoff sleep interrupted during BatchGetItem retry");
        }
    }

    public static long countMissingCredentials(int requestedCount, int returnedCount) {
        return Math.max(0, requestedCount - returnedCount);
    }
}
