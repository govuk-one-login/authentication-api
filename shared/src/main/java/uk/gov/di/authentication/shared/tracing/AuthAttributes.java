package uk.gov.di.authentication.shared.tracing;

import io.opentelemetry.api.common.AttributeKey;

public class AuthAttributes {
    public static final AttributeKey<String> SESSION_ID = AttributeKey.stringKey("session_id");
    public static final AttributeKey<String> AUTH_SESSION_ID =
            AttributeKey.stringKey("auth_session_id");
    public static final AttributeKey<String> ORCH_SESSION_ID =
            AttributeKey.stringKey("orch_session_id");
    public static final AttributeKey<String> PERSISTENT_SESSION_ID =
            AttributeKey.stringKey("persistent_session_id");
    public static final AttributeKey<String> CLIENT_ID = AttributeKey.stringKey("client_id");
}
