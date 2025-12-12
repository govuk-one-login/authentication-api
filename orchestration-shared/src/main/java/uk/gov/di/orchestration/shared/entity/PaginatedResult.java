package uk.gov.di.orchestration.shared.entity;

import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

import java.util.List;
import java.util.Map;

public class PaginatedResult<T> {
    private final List<T> items;
    private final Map<String, AttributeValue> lastEvaluatedKey;

    public PaginatedResult(List<T> items, Map<String, AttributeValue> lastEvaluatedKey) {
        this.items = items;
        this.lastEvaluatedKey = lastEvaluatedKey;
    }

    public List<T> getItems() {
        return items;
    }

    public Map<String, AttributeValue> getLastEvaluatedKey() {
        return lastEvaluatedKey;
    }

    public boolean hasMoreResults() {
        return lastEvaluatedKey != null && !lastEvaluatedKey.isEmpty();
    }
}
