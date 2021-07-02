package uk.gov.di.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SendNotificationResponse extends BaseAPIResponse {
    public SendNotificationResponse(@JsonProperty("sessionState") SessionState sessionState) {
        super(sessionState);
    }
}
