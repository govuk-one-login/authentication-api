package uk.gov.di.authentication.accountdata.helpers;

import uk.gov.di.authentication.accountdata.entity.passkey.Passkey;

import java.time.LocalDateTime;
import java.util.List;

import static uk.gov.di.authentication.accountdata.helpers.PasskeysHelper.buildSortKey;

public class PasskeysTestHelper {

    public static Passkey buildGenericPasskeyForUserWithSubjectId(
            String publicSubjectId, String passkeyId) {
        return buildPasskeyForUser(
                publicSubjectId,
                CommonTestVariables.CREDENTIAL,
                passkeyId,
                CommonTestVariables.PASSKEY_AAGUID,
                true,
                1,
                CommonTestVariables.PASSKEY_TRANSPORTS,
                true,
                false);
    }

    public static Passkey buildPasskeyForUser(
            String publicSubjectId,
            String credential,
            String passkeyId,
            String aaguid,
            boolean isAttested,
            int signCount,
            List<String> transports,
            boolean backupEligible,
            boolean backedUp) {
        var created = LocalDateTime.now().toString();
        return new Passkey()
                .withPublicSubjectId(publicSubjectId)
                .withSortKey(buildSortKey(passkeyId))
                .withCredentialId(passkeyId)
                .withCreated(created)
                .withCredential(credential)
                .withPasskeyAaguid(aaguid)
                .withPasskeyIsAttested(isAttested)
                .withPasskeySignCount(signCount)
                .withPasskeyTransports(transports)
                .withPasskeyBackupEligible(backupEligible)
                .withPasskeyBackedUp(backedUp);
    }
}
