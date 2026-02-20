package uk.gov.di.authentication.accountdata.services;

import uk.gov.di.authentication.accountdata.constants.AccountDataConstants;
import uk.gov.di.authentication.accountdata.entity.Authenticator;
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
        return getAllByPrefix(publicSubjectId, AccountDataConstants.PASSKEY_TYPE);
    }

    public Optional<Passkey> getPasskeyForUserWithPasskeyId(
            String publicSubjectId, String passkeyId) {
        return get(publicSubjectId, buildSortKey(passkeyId));
    }

    public boolean savePasskeyIfUnique(
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
        var passkey =
                new Passkey()
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

        return putIfUnique(passkey, Authenticator.ATTRIBUTE_SORT_KEY);
    }

    public void updatePasskey(String publicSubjectId, String passkeyId, String lastUsed) {
        getPasskeyForUserWithPasskeyId(publicSubjectId, passkeyId)
                .ifPresent(
                        pk -> {
                            pk.setLastUsed(lastUsed);
                            update(pk);
                        });
    }

    public void deletePasskey(String publicSubjectId, String passkeyId) {
        var sortKey = buildSortKey(passkeyId);
        delete(publicSubjectId, sortKey);
    }

    private String buildSortKey(String passkeyId) {
        return AccountDataConstants.PASSKEY_TYPE + "#" + passkeyId;
    }
}
