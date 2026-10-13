package uk.gov.di.authentication.accountdata.services;

import uk.gov.di.authentication.accountdata.constants.AccountDataConstants;
import uk.gov.di.authentication.accountdata.entity.Authenticator;
import uk.gov.di.authentication.accountdata.entity.passkey.Passkey;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysCreateFailureReason;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysDeleteFailureReason;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysUpdateFailureReason;
import uk.gov.di.authentication.shared.entity.Result;

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

    public Result<PasskeysCreateFailureReason, Void> savePasskeyIfUnique(Passkey passkey) {
        try {
            var passkeySaved = putIfUnique(passkey, Authenticator.ATTRIBUTE_SORT_KEY);
            return passkeySaved
                    ? Result.success(null)
                    : Result.failure(PasskeysCreateFailureReason.PASSKEY_EXISTS);
        } catch (Exception e) {
            return Result.failure(PasskeysCreateFailureReason.FAILED_TO_SAVE_PASSKEY);
        }
    }

    public Result<PasskeysUpdateFailureReason, Passkey> updatePasskey(
            String publicSubjectId, String passkeyId, String lastUsed, long signCount) {
        var existingPasskey = getPasskeyForUserWithPasskeyId(publicSubjectId, passkeyId);
        if (existingPasskey.isEmpty()) {
            return Result.failure(PasskeysUpdateFailureReason.PASSKEY_NOT_FOUND);
        }
        var passkey = existingPasskey.get();
        passkey.withLastUsed(lastUsed).withPasskeySignCount(signCount);
        update(passkey);
        return Result.success(passkey);
    }

    public Result<PasskeysDeleteFailureReason, Void> deletePasskey(
            String publicSubjectId, String passkeyId) {
        var existingPasskey = getPasskeyForUserWithPasskeyId(publicSubjectId, passkeyId);
        if (existingPasskey.isEmpty()) {
            return Result.failure(PasskeysDeleteFailureReason.PASSKEY_NOT_FOUND);
        }
        delete(existingPasskey.get());
        return Result.success(null);
    }
}
