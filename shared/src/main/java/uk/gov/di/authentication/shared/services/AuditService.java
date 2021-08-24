package uk.gov.di.authentication.shared.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.domain.AuditableEvent;

import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Collectors;

public class AuditService {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuditService.class);

    public void submitAuditEvent(AuditableEvent event, MetadataPair... metadataPairs) {
        LOGGER.info(generateLogLine(event, metadataPairs));
    }

    String generateLogLine(AuditableEvent event, MetadataPair... metadataPairs) {
        var baseLogLine = "Emitting audit event - " + event;

        if (metadataPairs.length == 0) {
            return baseLogLine;
        }

        var keyValuePairs =
                Arrays.stream(metadataPairs)
                        .map(MetadataPair::toString)
                        .collect(Collectors.joining(", "));

        return baseLogLine + " => " + keyValuePairs;
    }

    public static class MetadataPair {
        private final String key;
        private final Object value;

        private MetadataPair(String key, Object value) {
            this.key = key;
            this.value = value;
        }

        public static MetadataPair pair(String key, Object value) {
            return new MetadataPair(key, value);
        }

        @Override
        public String toString() {
            return String.format("[%s: %s]", key, value);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            MetadataPair that = (MetadataPair) o;
            return Objects.equals(key, that.key) && Objects.equals(value, that.value);
        }

        @Override
        public int hashCode() {
            return Objects.hash(key, value);
        }
    }
}
