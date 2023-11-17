package uk.gov.di.orchestration.shared.services;

import uk.gov.di.orchestration.shared.entity.AccountModifiers;
import uk.gov.di.orchestration.shared.entity.AccountRecovery;
import uk.gov.di.orchestration.shared.helpers.NowHelper;

import java.util.Optional;

public class DynamoAccountModifiersService extends BaseDynamoService<AccountModifiers> {

    public DynamoAccountModifiersService(ConfigurationService configurationService) {
        super(AccountModifiers.class, "account-modifiers", configurationService);
    }

    public void setAccountRecoveryBlock(
            String internalCommonSubjectId, boolean accountRecoveryBlock) {
        var dateTime = NowHelper.toTimestampString(NowHelper.now());

        var accountModifiers =
                getAccountModifiers(internalCommonSubjectId)
                        .orElse(
                                new AccountModifiers()
                                        .withInternalCommonSubjectIdentifier(
                                                internalCommonSubjectId)
                                        .withCreated(dateTime))
                        .withUpdated(dateTime);

        accountModifiers.withAccountRecovery(
                Optional.of(accountModifiers)
                        .map(AccountModifiers::getAccountRecovery)
                        .orElse(new AccountRecovery().withCreated(dateTime))
                        .withBlocked(accountRecoveryBlock)
                        .withUpdated(dateTime));

        update(accountModifiers);
    }

    public Optional<AccountModifiers> getAccountModifiers(String internalCommonSubjectId) {
        return get(internalCommonSubjectId);
    }

    public boolean isAccountRecoveryBlockPresent(String internalCommonSubjectId) {
        return getAccountModifiers(internalCommonSubjectId)
                .map(AccountModifiers::getAccountRecovery)
                .filter(AccountRecovery::isBlocked)
                .isPresent();
    }

    public void removeAccountRecoveryBlockIfPresent(String internalCommonSubjectId) {
        if (isAccountRecoveryBlockPresent(internalCommonSubjectId)) {
            setAccountRecoveryBlock(internalCommonSubjectId, false);
        }
    }
}
