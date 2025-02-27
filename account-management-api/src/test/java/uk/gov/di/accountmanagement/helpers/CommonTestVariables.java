package uk.gov.di.accountmanagement.helpers;

import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;

import java.util.Map;

public class CommonTestVariables {
    public static final String PERSISTENT_ID = "some-persistent-session-id";
    public static final String SESSION_ID = "some-session-id";
    public static final String TXMA_ENCODED_HEADER_VALUE = "txma-test-value";
    public static final Map<String, String> VALID_HEADERS =
            Map.of(
                    PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                    PERSISTENT_ID,
                    ClientSessionIdHelper.SESSION_ID_HEADER_NAME,
                    SESSION_ID,
                    AuditHelper.TXMA_ENCODED_HEADER_NAME,
                    TXMA_ENCODED_HEADER_VALUE);
}
