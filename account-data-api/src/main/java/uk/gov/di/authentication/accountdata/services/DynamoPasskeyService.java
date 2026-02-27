package uk.gov.di.authentication.accountdata.services;

import uk.gov.di.authentication.accountdata.constants.AccountDataConstants;
import uk.gov.di.authentication.accountdata.entity.Authenticator;
import uk.gov.di.authentication.accountdata.entity.passkey.Passkey;
import uk.gov.di.authentication.shared.services.BaseDynamoService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;
import java.util.Optional;

import static uk.gov.di.authentication.accountdata.helpers.PasskeysHelper.buildSortKey;

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

    public boolean savePasskeyIfUnique(Passkey passkey) {
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
}
