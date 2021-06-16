package uk.gov.di.entity;

import java.time.LocalDateTime;

public class NotificationCode {

    private String code;
    private LocalDateTime timeOfIssue;

    public NotificationCode(String code, LocalDateTime timeOfIssue) {
        this.code = code;
        this.timeOfIssue = timeOfIssue;
    }

    public String getCode() {
        return code;
    }

    public LocalDateTime getTimeOfIssue() {
        return timeOfIssue;
    }
}
