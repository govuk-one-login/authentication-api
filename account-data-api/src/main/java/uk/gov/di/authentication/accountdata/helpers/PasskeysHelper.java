package uk.gov.di.authentication.accountdata.helpers;

import uk.gov.di.authentication.accountdata.constants.AccountDataConstants;

public class PasskeysHelper {

    private PasskeysHelper() {}

    public static String buildSortKey(String passkeyId) {
        return AccountDataConstants.PASSKEY_TYPE + "#" + passkeyId;
    }
}
