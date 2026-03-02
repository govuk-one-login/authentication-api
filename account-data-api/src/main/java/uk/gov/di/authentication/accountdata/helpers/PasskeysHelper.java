package uk.gov.di.authentication.accountdata.helpers;

import uk.gov.di.authentication.accountdata.constants.AccountDataConstants;

import java.util.UUID;

public class PasskeysHelper {

    private PasskeysHelper() {}

    public static String buildSortKey(String passkeyId) {
        return AccountDataConstants.PASSKEY_TYPE + "#" + passkeyId;
    }

    public static boolean isAaguidValid(String aaguid) {
        if (aaguid == null || aaguid.trim().isEmpty()) {
            return false;
        }

        try {
            UUID.fromString(aaguid);
        } catch (IllegalArgumentException e) {
            return false;
        }

        return true;
    }
}
