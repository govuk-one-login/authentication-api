package uk.gov.di.authentication.accountdata.helpers;

import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;

import java.util.List;
import java.util.Map;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.TxmaAuditHelper.TXMA_AUDIT_ENCODED_HEADER;

public class CommonTestVariables {

    public static final String PUBLIC_SUBJECT_ID = "public-subject-id";
    public static final String ANOTHER_PUBLIC_SUBJECT_ID = "another-public-subject-id";
    public static final String PRIMARY_PASSKEY_ID = "primary-passkey-id";
    public static final String SECONDARY_PASSKEY_ID = "secondary-passkey-id";
    public static final String ANOTHER_USER_PASSKEY_ID = "another-user-passkey-id";
    public static final String PASSKEY_AAGUID = "passkey-aaguid";
    public static final List<String> PASSKEY_TRANSPORTS = List.of("internal", "hybrid");
    public static final String DI_PERSISTENT_SESSION_ID = "some-persistent-id-value";
    public static final String SESSION_ID = "session-id";
    public static final String CLIENT_SESSION_ID = "known-client-session-id";
    public static final String TEST_AAGUID = "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4";
    public static final String ENCODED_DEVICE_DETAILS =
            "YTtKVSlub1YlOSBTeEI4J3pVLVd7Jjl8VkBfREs2N3clZmN+fnU7fXNbcTJjKyEzN2IuUXIgMGttV058fGhUZ0xhenZUdldEblB8SH18XypwXUhWPXhYXTNQeURW%";
    public static final String CREDENTIAL = "credential";
    public static final String IP_ADDRESS = "123.123.123.123";
    public static final Map<String, String> VALID_HEADERS =
            Map.ofEntries(
                    Map.entry(
                            PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, DI_PERSISTENT_SESSION_ID),
                    Map.entry(SESSION_ID_HEADER, SESSION_ID),
                    Map.entry(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID),
                    Map.entry(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS));
}
