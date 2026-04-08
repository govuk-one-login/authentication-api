package uk.gov.di.authentication.oidc.entity;

import software.amazon.awssdk.enhanced.dynamodb.extensions.annotations.DynamoDbAtomicCounter;
import software.amazon.awssdk.enhanced.dynamodb.internal.converter.attribute.LocalDateTimeAttributeConverter;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbConvertedBy;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;

import java.time.LocalDateTime;

@DynamoDbBean
public class SlidingWindowData {

    public static final String ATTRIBUTE_CLIENT_ID = "ClientId";
    public static final String ATTRIBUTE_PERIOD_START_TIME = "PeriodStartTime";
    public static final String ATTRIBUTE_REQUEST_COUNT = "RequestCount";
    public static final String ATTRIBUTE_TTL = "ttl";

    private String clientId;
    private LocalDateTime periodStartTime;
    private Long requestCount;
    private long timeToLive;

    public SlidingWindowData() {}

    public SlidingWindowData(String clientId, LocalDateTime periodStartTime) {
        this.clientId = clientId;
        this.periodStartTime = periodStartTime;
    }

    public SlidingWindowData(
            String clientId, LocalDateTime periodStartTime, Long requestCount, long timeToLive) {
        this.clientId = clientId;
        this.periodStartTime = periodStartTime;
        this.requestCount = requestCount;
        this.timeToLive = timeToLive;
    }

    @DynamoDbPartitionKey
    @DynamoDbAttribute(ATTRIBUTE_CLIENT_ID)
    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public SlidingWindowData withClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    @DynamoDbSortKey
    @DynamoDbAttribute(ATTRIBUTE_PERIOD_START_TIME)
    @DynamoDbConvertedBy(LocalDateTimeAttributeConverter.class)
    public LocalDateTime getPeriodStartTime() {
        return periodStartTime;
    }

    public void setPeriodStartTime(LocalDateTime periodStartTime) {
        this.periodStartTime = periodStartTime;
    }

    public SlidingWindowData withPeriodStartTime(LocalDateTime periodStartTime) {
        this.periodStartTime = periodStartTime;
        return this;
    }

    @DynamoDbAtomicCounter(startValue = 1L)
    public Long getRequestCount() {
        return requestCount;
    }

    public void setRequestCount(Long requestCount) {
        this.requestCount = requestCount;
    }

    public SlidingWindowData withRequestCount(Long requestCount) {
        this.requestCount = requestCount;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_TTL)
    public long getTimeToLive() {
        return timeToLive;
    }

    public void setTimeToLive(long timeToLive) {
        this.timeToLive = timeToLive;
    }

    public SlidingWindowData withTimeToLive(long timeToLive) {
        this.timeToLive = timeToLive;
        return this;
    }
}
