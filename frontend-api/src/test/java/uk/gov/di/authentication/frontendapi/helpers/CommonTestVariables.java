package uk.gov.di.authentication.frontendapi.helpers;

import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;

import java.util.Map;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.lambda.BaseFrontendHandler.TXMA_AUDIT_ENCODED_HEADER;

public class CommonTestVariables {

    public static final String EMAIL = "joe.bloggs@test.com";
    public static final String PASSWORD = "computer-1";
    public static final String UK_MOBILE_NUMBER = "+447234567890";
    public static final String IP_ADDRESS = "123.123.123.123";
    public static final String DI_PERSISTENT_SESSION_ID = "some-persistent-id-value";
    public static final String ENCODED_DEVICE_DETAILS =
            "YTtKVSlub1YlOSBTeEI4J3pVLVd7Jjl8VkBfREs2N3clZmN+fnU7fXNbcTJjKyEzN2IuUXIgMGttV058fGhUZ0xhenZUdldEblB8SH18XypwXUhWPXhYXTNQeURW%";
    public static final String SESSION_ID = "session-id";
    public static final String CLIENT_SESSION_ID = "known-client-session-id";
    public static final Map<String, String> VALID_HEADERS =
            Map.ofEntries(
                    Map.entry(
                            PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, DI_PERSISTENT_SESSION_ID),
                    Map.entry(SESSION_ID_HEADER, SESSION_ID),
                    Map.entry(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID),
                    Map.entry(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS));

    public static final Map<String, String> VALID_HEADERS_WITHOUT_AUDIT_ENCODED =
            Map.ofEntries(
                    Map.entry(
                            PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, DI_PERSISTENT_SESSION_ID),
                    Map.entry(SESSION_ID_HEADER, SESSION_ID),
                    Map.entry(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID));
}
