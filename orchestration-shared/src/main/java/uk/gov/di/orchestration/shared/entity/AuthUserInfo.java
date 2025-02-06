package uk.gov.di.orchestration.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;

@DynamoDbBean
public class AuthUserInfo {

    private String internalCommonSubjectId;
    private String clientSessionId;
    private String userInfo;
    private long timeToExist;

    @DynamoDbPartitionKey
    @DynamoDbAttribute("InternalCommonSubjectId")
    public String getInternalCommonSubjectId() {
        return internalCommonSubjectId;
    }

    public void setInternalCommonSubjectId(String internalCommonSubjectId) {
        this.internalCommonSubjectId = internalCommonSubjectId;
    }

    public AuthUserInfo withInternalCommonSubjectId(String internalCommonSubjectId) {
        this.internalCommonSubjectId = internalCommonSubjectId;
        return this;
    }

    @DynamoDbSortKey
    @DynamoDbAttribute("ClientSessionId")
    public String getClientSessionId() {
        return clientSessionId;
    }

    public void setClientSessionId(String clientSessionId) {
        this.clientSessionId = clientSessionId;
    }

    public AuthUserInfo withClientSessionId(String clientSessionId) {
        this.clientSessionId = clientSessionId;
        return this;
    }

    @DynamoDbAttribute("UserInfo")
    public String getUserInfo() {
        return userInfo;
    }

    public void setUserInfo(String userInfo) {
        this.userInfo = userInfo;
    }

    public AuthUserInfo withUserInfo(String userInfo) {
        this.userInfo = userInfo;
        return this;
    }

    @DynamoDbAttribute("TimeToExist")
    public long getTimeToExist() {
        return timeToExist;
    }

    public void setTimeToExist(long timeToExist) {
        this.timeToExist = timeToExist;
    }

    public AuthUserInfo withTimeToExist(long timeToExist) {
        this.timeToExist = timeToExist;
        return this;
    }
}
