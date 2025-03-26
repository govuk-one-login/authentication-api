package uk.gov.di.orchestration.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

@DynamoDbBean
public class OrchAuthCodeItem {
    public static final String ATTRIBUTE_AUTH_CODE = "AuthCode";
    private static final String ATTRIBUTE_AUTH_CODE_EXCHANGE_DATA = "AuthCodeExchangeData";
    private static final String ATTRIBUTE_IS_USED = "IsUsed";
    private static final String ATTRIBUTE_TTL = "ttl";

    private String authCode;
    private String authCodeExchangeData;
    private boolean isUsed;
    private long timeToLive;

    public OrchAuthCodeItem() {}

    public OrchAuthCodeItem(OrchAuthCodeItem orchAuthCodeItem) {
        this.authCode = orchAuthCodeItem.authCode;
        this.authCodeExchangeData = orchAuthCodeItem.authCodeExchangeData;
        this.isUsed = orchAuthCodeItem.isUsed;
        this.timeToLive = orchAuthCodeItem.timeToLive;
    }

    @DynamoDbPartitionKey
    @DynamoDbAttribute(ATTRIBUTE_AUTH_CODE)
    public String getAuthCode() {
        return authCode;
    }

    public void setAuthCode(String authCode) {
        this.authCode = authCode;
    }

    public OrchAuthCodeItem withAuthCode(String authCode) {
        this.authCode = authCode;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_AUTH_CODE_EXCHANGE_DATA)
    public String getAuthCodeExchangeData() {
        return authCodeExchangeData;
    }

    public void setAuthCodeExchangeData(String authCodeExchangeData) {
        this.authCodeExchangeData = authCodeExchangeData;
    }

    public OrchAuthCodeItem withAuthCodeExchangeData(String authCodeExchangeData) {
        this.authCodeExchangeData = authCodeExchangeData;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_IS_USED)
    public boolean getIsUsed() {
        return isUsed;
    }

    public void setIsUsed(boolean isUsed) {
        this.isUsed = isUsed;
    }

    public OrchAuthCodeItem withIsUsed(boolean isUsed) {
        this.isUsed = isUsed;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_TTL)
    public long getTimeToLive() {
        return timeToLive;
    }

    public void setTimeToLive(long timeToLive) {
        this.timeToLive = timeToLive;
    }

    public OrchAuthCodeItem withTimeToLive(long timeToLive) {
        this.timeToLive = timeToLive;
        return this;
    }
}
