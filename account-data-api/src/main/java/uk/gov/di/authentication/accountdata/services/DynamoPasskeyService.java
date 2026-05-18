package uk.gov.di.authentication.accountdata.services;

import uk.gov.di.authentication.accountdata.constants.AccountDataConstants;
import uk.gov.di.authentication.accountdata.entity.Authenticator;
import uk.gov.di.authentication.accountdata.entity.passkey.Passkey;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysCreateFailureReason;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysDeleteFailureReason;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysUpdateFailureReason;
import uk.gov.di.authentication.shared.entity.Result;
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

    public Result<PasskeysCreateFailureReason, Void> savePasskeyIfUnique(Passkey passkey) {
        try {
            var passkeySaved = putIfUnique(passkey, Authenticator.ATTRIBUTE_SORT_KEY);
            return passkeySaved
                    ? Result.success(null)
                    : Result.failure(PasskeysCreateFailureReason.PASSKEY_EXISTS);
        } catch (Exception _) {
            return Result.failure(PasskeysCreateFailureReason.FAILED_TO_SAVE_PASSKEY);
        }
    }

    public Result<PasskeysUpdateFailureReason, Passkey> updatePasskey(
            String publicSubjectId, String passkeyId, String lastUsed, int signCount) {
        return getPasskeyForUserWithPasskeyId(publicSubjectId, passkeyId)
                .map(
                        passkey -> {
                            passkey.withLastUsed(lastUsed).withPasskeySignCount(signCount);
                            update(passkey);
                            return Result.<PasskeysUpdateFailureReason, Passkey>success(passkey);
                        })
                .orElseGet(() -> Result.failure(PasskeysUpdateFailureReason.PASSKEY_NOT_FOUND));
    }

    public Result<PasskeysDeleteFailureReason, Void> deletePasskey(
            String publicSubjectId, String passkeyId) {
        return getPasskeyForUserWithPasskeyId(publicSubjectId, passkeyId)
                .map(
                        passkey -> {
                            delete(passkey);
                            return Result.<PasskeysDeleteFailureReason, Void>success(null);
                        })
                .orElseGet(() -> Result.failure(PasskeysDeleteFailureReason.PASSKEY_NOT_FOUND));
    }
}
