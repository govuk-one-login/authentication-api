package uk.gov.di.orchestration.sharedtest.helper;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.State;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

import static java.time.Clock.fixed;

public final class Constants {
    private Constants() {}

    public static final State STATE = new State();
    public static final AuthorizationCode AUTHORIZATION_CODE = new AuthorizationCode();
    public static final String ENVIRONMENT = "test";
    public static final String TEST_CLIENT_ID = "test-client-id";
    public static final String SESSION_ID = "session-id";
    public static final String CLIENT_SESSION_ID = "client-session-id";
    public static final String CLIENT_NAME = "test-client";
    public static final String TEST_BACKEND_URI = "https://api.example.com/oauth";
    public static final URI TEST_AUTHORIZE_URI = URI.create(TEST_BACKEND_URI + "/authorize");
    public static final URI TEST_TOKEN_URI = URI.create(TEST_BACKEND_URI + "/token");
    public static final URI TEST_USERINFO_URI = URI.create(TEST_BACKEND_URI + "/token");
    public static final URI TEST_CALLBACK_URI = URI.create("https://oidc.example.com/callback");
    public static final String TEST_SIGNING_KEY_ALIAS = "alias/oauth-signing-key";
    public static final String TEST_PRIVATE_KEY_JWT_AUDIENCE = TEST_TOKEN_URI.toString();
    public static final String TEST_STATE_PREFIX = "state::";
    public static final Instant FIXED_TIMESTAMP = Instant.parse("2021-09-01T22:10:00.012Z");
    public static final Clock FIXED_CLOCK = fixed(FIXED_TIMESTAMP, ZoneId.of("UTC"));
}
