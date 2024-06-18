package uk.gov.di.authentication.frontendapi.helpers;

import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;

import java.util.Map;

import static uk.gov.di.authentication.shared.lambda.BaseFrontendHandler.TXMA_AUDIT_ENCODED_HEADER;

public class CommonTestVariables {

    public static final String EMAIL = "joe.bloggs@test.com";
    public static final String PASSWORD = "computer-1";
    public static final String UK_MOBILE_NUMBER = "+447234567890";
    public static final String IP_ADDRESS = "123.123.123.123";
    public static final String CLIENT_SESSION_ID = "known-client-session-id";
    public static final String TEST_CLIENT_ID = "test_client_id";
    public static final String TEST_CLIENT_NAME = "test_client_name";
    public static final String CLIENT_SESSION_ID_HEADER = "Client-Session-Id";
    public static final String SESSION_ID_HEADER = "Session-Id";
    public static final String SESSION_ID = "some-session-id";
    public static final String PERSISTENT_ID = "some-persistent-id-value";
    public static final String ENCODED_DEVICE_DETAILS =
            "YTtKVSlub1YlOSBTeEI4J3pVLVd7Jjl8VkBfREs2N3clZmN+fnU7fXNbcTJjKyEzN2IuUXIgMGttV058fGhUZ0xhenZUdldEblB8SH18XypwXUhWPXhYXTNQeURW%";

    public static Map<String, String> validHeaders(Session session) {
        return Map.ofEntries(
                Map.entry(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID),
                Map.entry("Session-Id", session.getSessionId()),
                Map.entry(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID),
                Map.entry(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS));
    }

    public static Map<String, String> validHeadersWithoutTxmaAuditEncoded(Session session) {
        return Map.ofEntries(
                Map.entry(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID),
                Map.entry("Session-Id", session.getSessionId()),
                Map.entry(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID));
    }
}
