package uk.gov.di.authentication.sharedtest.helper;

import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;

import java.util.Map;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.lambda.BaseFrontendHandler.TXMA_AUDIT_ENCODED_HEADER;

/** Common values for use in tests. */
public class CommonTestVariables {

    private static final String emailUser = "test.user";
    private static final String emailDomain = "example.com";

    public static final String EMAIL = emailUser + "@" + emailDomain;
    public static final String EMAIL_BAD = buildTestEmail("bad");
    public static final String EMAIL_NEW = buildTestEmail("new");
    public static final String EMAIL_OLD = buildTestEmail("old");

    public static final String CLIENT_EMAIL = "test-client@" + emailDomain;

    public static final String PASSWORD = "test-password"; // pragma: allowlist secret
    public static final String PASSWORD_BAD = buildTestPassword("bad");
    public static final String PASSWORD_NEW = buildTestPassword("new");
    public static final String PASSWORD_OLD = buildTestPassword("old");
    public static final String VALID_PASSWORD = "ValidPassword123!"; // pragma: allowlist secret

    public static final String IP_ADDRESS = buildNet3Ip(1);

    public static final String UK_LANDLINE_NUMBER = "+441234567890";
    public static final String UK_LANDLINE_NUMBER_NO_CC = "01234567890";
    public static final String UK_MOBILE_NUMBER = "+447234567890";
    public static final String UK_MOBILE_NUMBER_NO_CC = "07234567890";
    public static final String BAD_PHONE_NUMBER = "not-a-number";

    public static final String UK_NOTIFY_MOBILE_TEST_NUMBER = "07700900000";

    public static final String NOTIFY_BEARER_TOKEN = "notify-test-@bearer-token";

    public static final String INTERNAL_SECTOR_HOST = "test.account.gov.uk";
    public static final String INTERNAL_SECTOR_URI = "https://" + INTERNAL_SECTOR_HOST;

    public static final String PERSISTENT_SESSION_ID = "some-persistent-id-value";
    public static final String ENCODED_DEVICE_DETAILS =
            // pragma: allowlist nextline secret
            "YTtKVSlub1YlOSBTeEI4J3pVLVd7Jjl8VkBfREs2N3clZmN+fnU7fXNbcTJjKyEzN2IuUXIgMGttV058fGhUZ0xhenZUdldEblB8SH18XypwXUhWPXhYXTNQeURW%";

    public static final String SESSION_ID = "session-id";
    public static final String CLIENT_SESSION_ID = "known-client-session-id";
    public static final String CLIENT_NAME = "client-name";
    public static final String CLIENT_ID = "client-id";
    public static final String COMMON_SUBJECT_ID = "urn:some:subject:identifier";

    public static final String IPV_CLIENT_ID = "some-ipv-client-id";

    public static final String AUTH_APP_SECRET =
            "JZ5PYIOWNZDAOBA65S5T77FEEKYCCIT2VE4RQDAJD7SO73T3LODA"; // pragma: allowlist secret

    public static final String PUBLIC_CERT_VALID =
            // pragma: allowlist nextline secret
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxt91w8GsMDdklOpS8ZXAsIM1ztQZd5QT/bRCQahZJeS1a6Os4hbuKwzHlz52zfTNp7BL4RB/KOcRIPhOQLgqeyM+bVngRa1EIfTkugJHS2/gu2Xv0aelwvXj8FZgAPRPD+ps2wiV4tUehrFIsRyHZM3yOp9g6qapCcxF7l0E1PlVkKPcPNmxn2oFiqnP6ZThGbE+N2avdXHcySIqt/v6Hbmk8cDHzSExazW7j/XvA+xnp0nQ5m2GisCZul5If5edCTXD0tKzx/I/gtEG4gkv9kENWOt4grP8/0zjNAl2ac6kpRny3tY5RkKBKCOB1VHwq2lUTSNKs32O1BsA5ByyYQIDAQAB";

    public static final String TXMA_ENCODED_HEADER_VALUE = TXMA_AUDIT_ENCODED_HEADER;
    public static final Map<String, String> VALID_HEADERS =
            Map.ofEntries(
                    Map.entry(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_SESSION_ID),
                    Map.entry(SESSION_ID_HEADER, SESSION_ID),
                    Map.entry(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID),
                    Map.entry(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS));

    public static final Map<String, String> VALID_HEADERS_WITHOUT_AUDIT_ENCODED =
            Map.ofEntries(
                    Map.entry(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_SESSION_ID),
                    Map.entry(SESSION_ID_HEADER, SESSION_ID),
                    Map.entry(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID));

    /**
     * Builds a test password by concatenating the base password with a given suffix.
     *
     * @param suffix the suffix to append to the base password
     * @return the constructed test password: {@link #PASSWORD}-{@code suffix}
     */
    public static String buildTestPassword(String suffix) {
        return PASSWORD + "-" + suffix;
    }

    /**
     * Builds a test password by concatenating the base password with a given suffix.
     *
     * @param suffix the suffix to append to the base password
     * @return the constructed test password: {@link #PASSWORD}-{@code suffix}
     */
    public static String buildTestPassword(Integer suffix) {
        return buildTestPassword(suffix.toString());
    }

    /**
     * Builds a test email by concatenating the base email user, subaddress, and email domain.
     *
     * @param subaddress the subaddress to append to the base email user
     * @return the constructed test email: {@link #emailUser}+{@code subaddress}+{@link
     *     #emailDomain}
     */
    public static String buildTestEmail(String subaddress) {
        return String.format("%s+%s@%s", emailUser, subaddress, emailDomain);
    }

    /**
     * Builds a test email address by concatenating the base email address with a given subaddress.
     *
     * @param subaddress the subaddress to append to the base email address
     * @return the constructed test email address: {@link #emailUser}+{@code subaddress}+{@link
     *     #emailDomain}
     */
    public static String buildTestEmail(Integer subaddress) {
        return buildTestEmail(subaddress.toString());
    }

    private static Boolean isValidLastOctet(Integer lastOctet) {
        return lastOctet >= 1 && lastOctet <= 254;
    }

    /**
     * Builds an IPv4 address within the TEST-NET-1 network (192.0.2.0/24).
     *
     * @param lastOctet the last octet to append to the base IP address
     * @return the constructed IP address: "192.0.2." + {@code lastOctet}
     * @throws IllegalArgumentException if {@code lastOctet} is not between 1 and 254 inclusive
     */
    public static String buildNet1Ip(Integer lastOctet) {
        if (!isValidLastOctet(lastOctet)) {
            throw new IllegalArgumentException("lastOctet must be between 1 and 254 inclusive");
        }
        return "192.0.2." + lastOctet.toString();
    }

    /**
     * Builds an IPv4 address within the TEST-NET-2 network (198.51.100.0/24).
     *
     * @param lastOctet the last octet to append to the base IP address
     * @return the constructed IP address: "198.51.100." + {@code lastOctet}
     * @throws IllegalArgumentException if {@code lastOctet} is not between 1 and 254 inclusive
     */
    public static String buildNet2Ip(Integer lastOctet) {
        if (!isValidLastOctet(lastOctet)) {
            throw new IllegalArgumentException("lastOctet must be between 1 and 254 inclusive");
        }
        return "198.51.100." + lastOctet.toString();
    }

    /**
     * Builds an IPv4 address within the TEST-NET-3 network (203.0.113.0/24).
     *
     * @param lastOctet the last octet to append to the base IP address
     * @return the constructed IP address: "203.0.113." + {@code lastOctet}
     * @throws IllegalArgumentException if {@code lastOctet} is not between 1 and 254 inclusive
     */
    public static String buildNet3Ip(Integer lastOctet) {
        if (!isValidLastOctet(lastOctet)) {
            throw new IllegalArgumentException("lastOctet must be between 1 and 254 inclusive");
        }
        return "203.0.113." + lastOctet.toString();
    }
}
