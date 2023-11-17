package uk.gov.di.orchestration.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

import java.util.Map;
import java.util.Objects;

@DynamoDbBean
public class TermsAndConditions {

    private String version;
    private String timestamp;

    public TermsAndConditions() {}

    public TermsAndConditions(String version, String timestamp) {
        this.version = version;
        this.timestamp = timestamp;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    AttributeValue toAttributeValue() {
        return AttributeValue.builder()
                .m(
                        Map.ofEntries(
                                Map.entry("version", AttributeValue.fromS(getVersion())),
                                Map.entry("timestamp", AttributeValue.fromS(getTimestamp()))))
                .build();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TermsAndConditions that = (TermsAndConditions) o;
        return Objects.equals(version, that.version) && Objects.equals(timestamp, that.timestamp);
    }

    @Override
    public int hashCode() {
        return Objects.hash(version, timestamp);
    }
}
