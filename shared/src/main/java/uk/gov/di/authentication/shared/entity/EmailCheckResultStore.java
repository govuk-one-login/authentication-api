package uk.gov.di.authentication.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbConvertedBy;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.authentication.shared.converters.ObjectConverter;

@DynamoDbBean
public class EmailCheckResultStore {

    public static final String ATTRIBUTE_EMAIL = "Email";
    public static final String ATTRIBUTE_STATUS = "Status";
    public static final String ATTRIBUTE_TIME_TO_EXIST = "TimeToExist";
    public static final String ATTRIBUTE_REFERENCE_NUMBER = "ReferenceNumber";
    public static final String ATTRIBUTE_GOVUK_SIGNIN_JOURNEY_ID = "GovukSigninJourneyId";
    public static final String ATTRIBUTE_EMAIL_CHECK_RESPONSE = "EmailCheckResponse";

    private String email;
    private EmailCheckResultStatus status;
    private long timeToExist;
    private String referenceNumber;
    private String govukSigninJourneyId;
    private Object emailCheckResponse;

    @DynamoDbPartitionKey
    @DynamoDbAttribute(ATTRIBUTE_EMAIL)
    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public EmailCheckResultStore withEmail(String email) {
        this.email = email;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_STATUS)
    public EmailCheckResultStatus getStatus() {
        return status;
    }

    public void setStatus(EmailCheckResultStatus status) {
        this.status = status;
    }

    public EmailCheckResultStore withStatus(EmailCheckResultStatus status) {
        this.status = status;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_TIME_TO_EXIST)
    public long getTimeToExist() {
        return timeToExist;
    }

    public void setTimeToExist(long timeToExist) {
        this.timeToExist = timeToExist;
    }

    public EmailCheckResultStore withTimeToExist(long timeToExist) {
        this.timeToExist = timeToExist;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_REFERENCE_NUMBER)
    public String getReferenceNumber() {
        return referenceNumber;
    }

    public void setReferenceNumber(String referenceNumber) {
        this.referenceNumber = referenceNumber;
    }

    public EmailCheckResultStore withReferenceNumber(String referenceNumber) {
        this.referenceNumber = referenceNumber;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_GOVUK_SIGNIN_JOURNEY_ID)
    public String getGovukSigninJourneyId() {
        return govukSigninJourneyId;
    }

    public void setGovukSigninJourneyId(String govukSigninJourneyId) {
        this.govukSigninJourneyId = govukSigninJourneyId;
    }

    public EmailCheckResultStore withGovukSigninJourneyId(String govukSigninJourneyId) {
        this.govukSigninJourneyId = govukSigninJourneyId;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_EMAIL_CHECK_RESPONSE)
    @DynamoDbConvertedBy(ObjectConverter.class)
    public Object getEmailCheckResponse() {
        return emailCheckResponse;
    }

    public void setEmailCheckResponse(Object emailCheckResponse) {
        this.emailCheckResponse = emailCheckResponse;
    }

    public EmailCheckResultStore withEmailCheckResponse(Object emailCheckResponse) {
        this.emailCheckResponse = emailCheckResponse;
        return this;
    }
}
