package uk.gov.di.authentication.entity;

public enum Application {
    AUTHENTICATION("Authentication"),
    ONE_LOGIN_HOME("OneLoginHome");

    private final String value;

    Application(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
