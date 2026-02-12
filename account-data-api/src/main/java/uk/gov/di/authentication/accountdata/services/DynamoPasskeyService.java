package uk.gov.di.authentication.accountdata.services;

import uk.gov.di.authentication.accountdata.constants.AccountDataConstants;
import uk.gov.di.authentication.accountdata.entity.passkey.Passkey;
import uk.gov.di.authentication.shared.services.BaseDynamoService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public class DynamoPasskeyService extends BaseDynamoService<Passkey> {

    public DynamoPasskeyService(ConfigurationService configurationService) {
        super(Passkey.class, "authenticator", configurationService);
    }

    public List<Passkey> getPasskeysForUser(String publicSubjectId) {
        return getAllByPrefix(publicSubjectId, AccountDataConstants.PASSKEY_CREDENTIAL);
    }

    public Optional<Passkey> getPasskeyForUserWithPasskeyId(
            String publicSubjectId, String passkeyId) {
        return get(publicSubjectId, buildSortKey(passkeyId));
    }

    public void savePasskey(
            String publicSubjectId,
            String passkeyId,
            String aaguid,
            boolean isAttested,
            int signCount,
            List<String> transports,
            boolean backupEligible,
            boolean backedUp) {
        var created = LocalDateTime.now().toString();
        var passkey =
                new Passkey()
                        .withPublicSubjectId(publicSubjectId)
                        .withSortKey(buildSortKey(passkeyId))
                        .withCredentialId(passkeyId)
                        .withCreated(created)
                        .withCredential(AccountDataConstants.PASSKEY_CREDENTIAL)
                        .withPasskeyAaguid(aaguid)
                        .withPasskeyIsAttested(isAttested)
                        .withPasskeySignCount(signCount)
                        .withPasskeyTransports(transports)
                        .withPasskeyBackupEligible(backupEligible)
                        .withPasskeyBackedUp(backedUp);

        put(passkey);
    }

    public Optional<Passkey> updatePasskey(
            String publicSubjectId, String passkeyId, String lastUsed) {
        return getPasskeyForUserWithPasskeyId(publicSubjectId, passkeyId)
                .map(
                        pk -> {
                            pk.setLastUsed(lastUsed);
                            update(pk);
                            return pk;
                        });
    }

    private String buildSortKey(String passkeyId) {
        return AccountDataConstants.PASSKEY_CREDENTIAL + "#" + passkeyId;
    }
}
