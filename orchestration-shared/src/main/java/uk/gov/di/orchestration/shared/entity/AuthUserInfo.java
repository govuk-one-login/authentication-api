package uk.gov.di.orchestration.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

@DynamoDbBean
public class AuthUserInfo {

    private String subjectID;
    private String userInfo;
    private long timeToExist;

    @DynamoDbPartitionKey
    @DynamoDbAttribute("SubjectID")
    public String getSubjectID() {
        return subjectID;
    }

    public void setSubjectID(String subjectID) {
        this.subjectID = subjectID;
    }

    public AuthUserInfo withSubjectID(String subjectID) {
        this.subjectID = subjectID;
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
