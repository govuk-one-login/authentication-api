package uk.gov.di.authentication.shared.services.mfa;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.MfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.request.MfaMethodCreateOrUpdateRequest;
import uk.gov.di.authentication.shared.entity.mfa.request.MfaMethodUpdateRequest;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestAuthAppMfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestSmsMfaDetail;
import uk.gov.di.authentication.shared.helpers.PhoneNumberHelper;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import static java.lang.String.format;
import static uk.gov.di.authentication.shared.conditions.MfaHelper.getPrimaryMFAMethod;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.BACKUP;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.DEFAULT;

public class MFAMethodsService {
    private static final Logger LOG = LogManager.getLogger(MFAMethodsService.class);

    private final AuthenticationService persistentService;

    public MFAMethodsService(ConfigurationService configurationService) {
        this.persistentService = new DynamoService(configurationService);
    }

    public Result<MfaRetrieveFailureReason, List<MFAMethod>> getMfaMethods(String email) {
        var userProfile = persistentService.getUserProfileByEmail(email);
        var userCredentials = persistentService.getUserCredentialsFromEmail(email);
        if (Boolean.TRUE.equals(userProfile.getMfaMethodsMigrated())) {
            return Result.success(getMfaMethodsForMigratedUser(userCredentials));
        } else {
            return getMfaMethodForNonMigratedUser(userProfile, userCredentials)
                    .map(optional -> optional.map(List::of).orElseGet(List::of));
        }
    }

    private List<MFAMethod> getMfaMethodsForMigratedUser(UserCredentials userCredentials) {
        return Optional.ofNullable(userCredentials.getMfaMethods()).orElse(new ArrayList<>());
    }

    public Result<MfaDeleteFailureReason, String> deleteMfaMethod(
            String mfaIdentifier, UserProfile userProfile) {
        if (!userProfile.getMfaMethodsMigrated()) {
            return Result.failure(
                    MfaDeleteFailureReason.CANNOT_DELETE_MFA_METHOD_FOR_NON_MIGRATED_USER);
        }

        var mfaMethods =
                persistentService
                        .getUserCredentialsFromEmail(userProfile.getEmail())
                        .getMfaMethods();

        var maybeMethodToDelete =
                mfaMethods.stream()
                        .filter(mfaMethod -> mfaIdentifier.equals(mfaMethod.getMfaIdentifier()))
                        .findFirst();

        if (maybeMethodToDelete.isEmpty()) {
            return Result.failure(MfaDeleteFailureReason.MFA_METHOD_WITH_IDENTIFIER_DOES_NOT_EXIST);
        }

        if (!BACKUP.name().equals(maybeMethodToDelete.get().getPriority())) {
            return Result.failure(MfaDeleteFailureReason.CANNOT_DELETE_DEFAULT_METHOD);
        }

        persistentService.deleteMfaMethodByIdentifier(userProfile.getEmail(), mfaIdentifier);
        return Result.success(mfaIdentifier);
    }

    private Result<MfaRetrieveFailureReason, Optional<MFAMethod>> getMfaMethodForNonMigratedUser(
            UserProfile userProfile, UserCredentials userCredentials) {
        var enabledAuthAppMethod = getPrimaryMFAMethod(userCredentials);
        if (enabledAuthAppMethod.filter(MFAMethod::isMethodVerified).isPresent()) {
            var method = enabledAuthAppMethod.get();
            String mfaIdentifier;
            if (Objects.nonNull(method.getMfaIdentifier())) {
                mfaIdentifier = method.getMfaIdentifier();
            } else {
                mfaIdentifier = UUID.randomUUID().toString();
                var result =
                        persistentService.setMfaIdentifierForNonMigratedUserEnabledAuthApp(
                                userProfile.getEmail(), mfaIdentifier);
                if (result.isFailure()) {
                    LOG.error(
                            "Unexpected error updating non migrated auth app mfa identifier: {}",
                            result.getFailure());
                    return Result.failure(
                            MfaRetrieveFailureReason
                                    .UNEXPECTED_ERROR_CREATING_MFA_IDENTIFIER_FOR_NON_MIGRATED_AUTH_APP);
                }
            }
            return Result.success(
                    Optional.of(
                            method.withMfaIdentifier(mfaIdentifier).withPriority(DEFAULT.name())));
        } else if (userProfile.isPhoneNumberVerified()) {
            String mfaIdentifier;
            if (Objects.nonNull(userProfile.getMfaIdentifier())) {
                mfaIdentifier = userProfile.getMfaIdentifier();
            } else {
                mfaIdentifier = UUID.randomUUID().toString();
                persistentService.setMfaIdentifierForNonMigratedSmsMethod(
                        userProfile.getEmail(), mfaIdentifier);
            }
            return Result.success(
                    Optional.of(
                            MFAMethod.smsMfaMethod(
                                    true,
                                    true,
                                    userProfile.getPhoneNumber(),
                                    DEFAULT,
                                    mfaIdentifier)));
        } else {
            return Result.success(Optional.empty());
        }
    }

    public Result<MfaCreateFailureReason, MFAMethod> addBackupMfa(
            String email, MfaMethodCreateOrUpdateRequest.MfaMethod mfaMethod) {
        UserCredentials userCredentials = persistentService.getUserCredentialsFromEmail(email);
        var mfaMethods = getMfaMethodsForMigratedUser(userCredentials);

        if (mfaMethods.size() >= 2) {
            return Result.failure(MfaCreateFailureReason.BACKUP_AND_DEFAULT_METHOD_ALREADY_EXIST);
        }

        if (mfaMethod.method() instanceof RequestSmsMfaDetail requestSmsMfaDetail) {
            var maybePhoneNumberWithCountryCode =
                    getPhoneNumberWithCountryCode(requestSmsMfaDetail.phoneNumber());

            if (maybePhoneNumberWithCountryCode.isFailure()) {
                LOG.warn(maybePhoneNumberWithCountryCode.getFailure());
                return Result.failure(MfaCreateFailureReason.INVALID_PHONE_NUMBER);
            }

            var phoneNumberWithCountryCode = maybePhoneNumberWithCountryCode.getSuccess();

            boolean phoneNumberExists =
                    mfaMethods.stream()
                            .filter(
                                    method ->
                                            method.getMfaMethodType()
                                                    .equals(MFAMethodType.SMS.getValue()))
                            .anyMatch(
                                    method ->
                                            method.getDestination()
                                                    .equalsIgnoreCase(phoneNumberWithCountryCode));

            if (phoneNumberExists) {
                return Result.failure(MfaCreateFailureReason.PHONE_NUMBER_ALREADY_EXISTS);
            }

            String uuid = UUID.randomUUID().toString();
            var smsMfaMethod =
                    MFAMethod.smsMfaMethod(
                            true,
                            true,
                            phoneNumberWithCountryCode,
                            mfaMethod.priorityIdentifier(),
                            uuid);
            persistentService.addMFAMethodSupportingMultiple(email, smsMfaMethod);
            return Result.success(smsMfaMethod);
        } else {
            boolean authAppExists = // TODO: Should this logic change to only look for "enabled"
                    // auth apps?
                    mfaMethods.stream()
                            .anyMatch(
                                    method ->
                                            method.getMfaMethodType()
                                                    .equals(MFAMethodType.AUTH_APP.getValue()));

            if (authAppExists) {
                return Result.failure(MfaCreateFailureReason.AUTH_APP_EXISTS);
            }

            String uuid = UUID.randomUUID().toString();
            var authAppMfaMethod =
                    MFAMethod.authAppMfaMethod(
                            ((RequestAuthAppMfaDetail) mfaMethod.method()).credential(),
                            true,
                            true,
                            mfaMethod.priorityIdentifier(),
                            uuid);
            persistentService.addMFAMethodSupportingMultiple(email, authAppMfaMethod);
            return Result.success(authAppMfaMethod);
        }
    }

    public Result<MfaUpdateFailureReason, List<MFAMethod>> updateMfaMethod(
            String email, String mfaIdentifier, MfaMethodUpdateRequest request) {
        var mfaMethods = persistentService.getUserCredentialsFromEmail(email).getMfaMethods();

        var maybeMethodToUpdate =
                mfaMethods.stream()
                        .filter(mfaMethod -> mfaIdentifier.equals(mfaMethod.getMfaIdentifier()))
                        .findFirst();

        return maybeMethodToUpdate
                .map(
                        method -> {
                            if (updateRequestChangesMethodType(
                                    method.getMfaMethodType(), request.mfaMethod().method())) {
                                return Result.<MfaUpdateFailureReason, List<MFAMethod>>failure(
                                        MfaUpdateFailureReason.CANNOT_CHANGE_TYPE_OF_MFA_METHOD);
                            } else {
                                return switch (PriorityIdentifier.valueOf(method.getPriority())) {
                                    case DEFAULT -> handleDefaultMethodUpdate(
                                            method,
                                            request.mfaMethod(),
                                            email,
                                            mfaIdentifier,
                                            mfaMethods);
                                    case BACKUP -> handleBackupMethodUpdate(
                                            method, request.mfaMethod(), email, mfaMethods);
                                };
                            }
                        })
                .orElse(Result.failure(MfaUpdateFailureReason.UNKOWN_MFA_IDENTIFIER));
    }

    private Result<MfaUpdateFailureReason, List<MFAMethod>> handleBackupMethodUpdate(
            MFAMethod backupMethod,
            MfaMethodUpdateRequest.MfaMethod updatedMethod,
            String email,
            List<MFAMethod> allMethods) {
        if (updatedMethod.method() instanceof RequestSmsMfaDetail updatedSmsDetail) {
            var maybePhoneNumberWithCountryCode =
                    getPhoneNumberWithCountryCode(updatedSmsDetail.phoneNumber());

            if (maybePhoneNumberWithCountryCode.isFailure()) {
                LOG.warn(maybePhoneNumberWithCountryCode.getFailure());
                return Result.failure(MfaUpdateFailureReason.INVALID_PHONE_NUMBER);
            }

            var phoneNumberWithCountryCode = maybePhoneNumberWithCountryCode.getSuccess();
            var changesPhoneNumber =
                    !phoneNumberWithCountryCode.equals(backupMethod.getDestination());
            if (changesPhoneNumber) {
                return Result.failure(
                        MfaUpdateFailureReason.ATTEMPT_TO_UPDATE_BACKUP_METHOD_PHONE_NUMBER);
            }
        } else {
            var authAppDetail = (RequestAuthAppMfaDetail) updatedMethod.method();
            var changesAuthAppCredential =
                    !authAppDetail.credential().equals(backupMethod.getCredentialValue());
            if (changesAuthAppCredential) {
                return Result.failure(
                        MfaUpdateFailureReason.ATTEMPT_TO_UPDATE_BACKUP_METHOD_AUTH_APP_CREDENTIAL);
            }
        }

        if (updatedMethod.priorityIdentifier().equals(BACKUP)) {
            return Result.failure(
                    MfaUpdateFailureReason.REQUEST_TO_UPDATE_MFA_METHOD_WITH_NO_CHANGE);
        }
        var maybeDefaultMethod =
                allMethods.stream()
                        .filter(m -> Objects.equals(m.getPriority(), DEFAULT.name()))
                        .findFirst();

        if (maybeDefaultMethod.isEmpty()) {
            return Result.failure(
                    MfaUpdateFailureReason.ATTEMPT_TO_UPDATE_BACKUP_WITH_NO_DEFAULT_METHOD);
        }

        var defaultMethod = maybeDefaultMethod.get();
        var databaseUpdateResult =
                persistentService.updateAllMfaMethodsForUser(
                        email,
                        List.of(
                                defaultMethod.withPriority(BACKUP.name()),
                                backupMethod.withPriority(DEFAULT.name())));

        return mfaUpdateFailureReasonOrSortedMfaMethods(databaseUpdateResult);
    }

    private Result<MfaUpdateFailureReason, List<MFAMethod>>
            mfaUpdateFailureReasonOrSortedMfaMethods(
                    Result<String, List<MFAMethod>> databaseUpdateResult) {
        return databaseUpdateResult
                .map(m -> m.stream().sorted().toList())
                .mapFailure(
                        errorString -> {
                            LOG.error(errorString);
                            return MfaUpdateFailureReason.UNEXPECTED_ERROR;
                        });
    }

    private Result<MfaUpdateFailureReason, List<MFAMethod>> handleDefaultMethodUpdate(
            MFAMethod defaultMethod,
            MfaMethodUpdateRequest.MfaMethod updatedMethod,
            String email,
            String mfaIdentifier,
            List<MFAMethod> allMethodsForUser) {
        var requestedPriority = updatedMethod.priorityIdentifier();
        if (requestedPriority == BACKUP) {
            return Result.failure(MfaUpdateFailureReason.CANNOT_CHANGE_PRIORITY_OF_DEFAULT_METHOD);
        }

        Result<String, List<MFAMethod>> databaseUpdateResult;

        if (updatedMethod.method() instanceof RequestSmsMfaDetail updatedSmsDetail) {
            var maybePhoneNumberWithCountryCode =
                    getPhoneNumberWithCountryCode(updatedSmsDetail.phoneNumber());

            if (maybePhoneNumberWithCountryCode.isFailure()) {
                LOG.warn(maybePhoneNumberWithCountryCode.getFailure());
                return Result.failure(MfaUpdateFailureReason.INVALID_PHONE_NUMBER);
            }

            var phoneNumberWithCountryCode = maybePhoneNumberWithCountryCode.getSuccess();
            var isExistingDefaultPhoneNumber =
                    phoneNumberWithCountryCode.equals(defaultMethod.getDestination());
            var otherMethods =
                    allMethodsForUser.stream()
                            .filter(
                                    mfaMethod ->
                                            !mfaMethod.getMfaIdentifier().equals(mfaIdentifier))
                            .toList();
            var isExistingBackupPhoneNumber =
                    otherMethods.stream()
                            .anyMatch(
                                    mfaMethod ->
                                            phoneNumberWithCountryCode.equals(
                                                    mfaMethod.getDestination()));
            if (isExistingDefaultPhoneNumber) {
                return Result.failure(
                        MfaUpdateFailureReason.REQUEST_TO_UPDATE_MFA_METHOD_WITH_NO_CHANGE);
            } else if (isExistingBackupPhoneNumber) {
                return Result.failure(
                        MfaUpdateFailureReason.ATTEMPT_TO_UPDATE_PHONE_NUMBER_WITH_BACKUP_NUMBER);
            } else {
                databaseUpdateResult =
                        persistentService.updateMigratedMethodPhoneNumber(
                                email, phoneNumberWithCountryCode, mfaIdentifier);
            }
        } else {
            var authAppDetail = (RequestAuthAppMfaDetail) updatedMethod.method();
            if (authAppDetail.credential().equals(defaultMethod.getCredentialValue())) {
                return Result.failure(
                        MfaUpdateFailureReason.REQUEST_TO_UPDATE_MFA_METHOD_WITH_NO_CHANGE);
            } else {
                databaseUpdateResult =
                        persistentService.updateMigratedAuthAppCredential(
                                email, authAppDetail.credential(), mfaIdentifier);
            }
        }

        return mfaUpdateFailureReasonOrSortedMfaMethods(databaseUpdateResult);
    }

    private boolean updateRequestChangesMethodType(
            String methodTypeFromExisting, MfaDetail updatedMethodDetail) {
        return updatedMethodDetail instanceof RequestAuthAppMfaDetail
                ? !MFAMethodType.AUTH_APP.name().equals(methodTypeFromExisting)
                : !MFAMethodType.SMS.name().equals(methodTypeFromExisting);
    }

    public Optional<MfaMigrationFailureReason> migrateMfaCredentialsForUser(String email) {
        // Bail if user doesn't exist
        Optional<UserProfile> maybeUserProfile = persistentService.getUserProfileFromEmail(email);
        Optional<UserCredentials> maybeUserCredentials =
                Optional.ofNullable(persistentService.getUserCredentialsFromEmail(email));
        if (maybeUserProfile.isEmpty() || maybeUserCredentials.isEmpty()) {
            return Optional.of(MfaMigrationFailureReason.NO_USER_FOUND_FOR_EMAIL);
        }

        UserProfile userProfile = maybeUserProfile.get();
        UserCredentials userCredentials = maybeUserCredentials.get();

        // Bail if already migrated
        if (userProfile.getMfaMethodsMigrated()) {
            return Optional.of(MfaMigrationFailureReason.ALREADY_MIGRATED);
        }

        var nonMigratedRetrieveResult =
                getMfaMethodForNonMigratedUser(userProfile, userCredentials);

        if (nonMigratedRetrieveResult.isFailure()) {
            return Optional.of(MfaMigrationFailureReason.UNEXPECTED_ERROR_RETRIEVING_METHODS);
        }

        var maybeNonMigratedMfaMethod = nonMigratedRetrieveResult.getSuccess();

        // Bail if no MFA methods to migrate
        if (maybeNonMigratedMfaMethod.isEmpty()) {
            persistentService.setMfaMethodsMigrated(email, true);
            return Optional.empty();
        }

        var nonMigratedMfaMethod = maybeNonMigratedMfaMethod.get();

        String mfaIdentifier;
        if (Objects.isNull(nonMigratedMfaMethod.getMfaIdentifier())) {
            mfaIdentifier = UUID.randomUUID().toString();
        } else {
            mfaIdentifier = nonMigratedMfaMethod.getMfaIdentifier();
        }

        return switch (MFAMethodType.valueOf(nonMigratedMfaMethod.getMfaMethodType())) {
            case SMS -> migrateSmsToNewFormat(
                    email, nonMigratedMfaMethod.getDestination(), mfaIdentifier);
            case AUTH_APP -> migrateAuthAppToNewFormat(
                    email, nonMigratedMfaMethod.getCredentialValue(), mfaIdentifier);
            default -> Optional.of(MfaMigrationFailureReason.UNEXPECTED_ERROR_RETRIEVING_METHODS);
        };
    }

    private Optional<MfaMigrationFailureReason> migrateAuthAppToNewFormat(
            String email, String credential, String identifier) {
        persistentService.overwriteMfaMethodToCredentialsAndDeleteProfilePhoneNumberForUser(
                email,
                MFAMethod.authAppMfaMethod(
                        credential, true, true, PriorityIdentifier.DEFAULT, identifier));
        return Optional.empty();
    }

    private Optional<MfaMigrationFailureReason> migrateSmsToNewFormat(
            String email, String phoneNumber, String identifier) {
        persistentService.overwriteMfaMethodToCredentialsAndDeleteProfilePhoneNumberForUser(
                email,
                MFAMethod.smsMfaMethod(
                        true, true, phoneNumber, PriorityIdentifier.DEFAULT, identifier));

        return Optional.empty();
    }

    private Result<String, String> getPhoneNumberWithCountryCode(String phoneNumber) {
        try {
            return Result.success(PhoneNumberHelper.formatPhoneNumber(phoneNumber));
        } catch (Exception e) {
            return Result.failure(
                    format(
                            "Could not convert phone number %s to phone number with country code",
                            phoneNumber));
        }
    }
}
