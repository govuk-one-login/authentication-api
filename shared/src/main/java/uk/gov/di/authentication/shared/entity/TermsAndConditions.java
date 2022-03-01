package uk.gov.di.authentication.shared.entity;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBDocument;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;

import java.util.Map;
import java.util.Objects;

@DynamoDBDocument
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
        return new AttributeValue()
                .withM(
                        Map.ofEntries(
                                Map.entry("version", new AttributeValue(getVersion())),
                                Map.entry("timestamp", new AttributeValue(getTimestamp()))));
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
