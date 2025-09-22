package uk.gov.di.orchestration.sharedtest.helper;

import com.nimbusds.oauth2.sdk.id.State;

public final class Constants {
    private Constants() {}

    public static final State STATE = new State();
    public static final String ENVIRONMENT = "test";
    public static final String TEST_CLIENT_ID = "test-client-id";
    public static final String SESSION_ID = "session-id";
    public static final String CLIENT_SESSION_ID = "client-session-id";
    public static final String CLIENT_NAME = "test-client";
}
