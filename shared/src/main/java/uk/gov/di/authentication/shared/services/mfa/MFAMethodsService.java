package uk.gov.di.authentication.shared.services.mfa;

import io.vavr.Value;
import io.vavr.control.Either;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.AuthAppMfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.MfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.MfaMethodCreateOrUpdateRequest;
import uk.gov.di.authentication.shared.entity.mfa.MfaMethodData;
import uk.gov.di.authentication.shared.entity.mfa.SmsMfaDetail;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import static uk.gov.di.authentication.shared.conditions.MfaHelper.getPrimaryMFAMethod;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.BACKUP;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.DEFAULT;

public class MFAMethodsService {
    private static final Logger LOG = LogManager.getLogger(MFAMethodsService.class);

    private final AuthenticationService persistentService;

    public MFAMethodsService(ConfigurationService configurationService) {
        this.persistentService = new DynamoService(configurationService);
    }

    public Either<MfaRetrieveFailureReason, List<MfaMethodData>> getMfaMethods(String email) {
        var userProfile = persistentService.getUserProfileByEmail(email);
        var userCredentials = persistentService.getUserCredentialsFromEmail(email);
        if (Boolean.TRUE.equals(userProfile.getMfaMethodsMigrated())) {
            return getMfaMethodsForMigratedUser(userCredentials);
        } else {
            return getMfaMethodForNonMigratedUser(userProfile, userCredentials)
                    .map(optional -> optional.map(List::of).orElseGet(List::of));
        }
    }

    private Either<MfaRetrieveFailureReason, List<MfaMethodData>> getMfaMethodsForMigratedUser(
            UserCredentials userCredentials) {
        List<Either<MfaRetrieveFailureReason, MfaMethodData>> mfaMethodDataResults =
                Optional.ofNullable(userCredentials.getMfaMethods())
                        .orElse(new ArrayList<>())
                        .stream()
                        .map(
                                mfaMethod -> {
                                    var mfaMethodData = MfaMethodData.from(mfaMethod);
                                    if (mfaMethodData.isLeft()) {
                                        LOG.error(
                                                "Error converting mfa method with type {} to mfa method data: {}",
                                                mfaMethod.getMfaMethodType(),
                                                mfaMethodData.getLeft());
                                        return Either.<MfaRetrieveFailureReason, MfaMethodData>left(
                                                MfaRetrieveFailureReason
                                                        .ERROR_CONVERTING_MFA_METHOD_TO_MFA_METHOD_DATA);
                                    } else {
                                        return Either
                                                .<MfaRetrieveFailureReason, MfaMethodData>right(
                                                        mfaMethodData.get());
                                    }
                                })
                        .toList();
        return Either.sequenceRight(io.vavr.collection.List.ofAll(mfaMethodDataResults))
                .map(Value::toJavaList);
    }

    public Either<MfaDeleteFailureReason, String> deleteMfaMethod(
            String mfaIdentifier, UserProfile userProfile) {
        if (!userProfile.getMfaMethodsMigrated()) {
            return Either.left(
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
            return Either.left(MfaDeleteFailureReason.MFA_METHOD_WITH_IDENTIFIER_DOES_NOT_EXIST);
        }

        if (!BACKUP.name().equals(maybeMethodToDelete.get().getPriority())) {
            return Either.left(MfaDeleteFailureReason.CANNOT_DELETE_DEFAULT_METHOD);
        }

        persistentService.deleteMfaMethodByIdentifier(userProfile.getEmail(), mfaIdentifier);
        return Either.right(mfaIdentifier);
    }

    private Either<MfaRetrieveFailureReason, Optional<MfaMethodData>>
            getMfaMethodForNonMigratedUser(
                    UserProfile userProfile, UserCredentials userCredentials) {
        var enabledAuthAppMethod = getPrimaryMFAMethod(userCredentials);
        if (enabledAuthAppMethod.isPresent()) {
            var method = enabledAuthAppMethod.get();
            String mfaIdentifier;
            if (Objects.nonNull(method.getMfaIdentifier())) {
                mfaIdentifier = method.getMfaIdentifier();
            } else {
                mfaIdentifier = UUID.randomUUID().toString();
                var result =
                        persistentService.setMfaIdentifierForNonMigratedUserEnabledAuthApp(
                                userProfile.getEmail(), mfaIdentifier);
                if (result.isLeft()) {
                    LOG.error(
                            "Unexpected error updating non migrated auth app mfa identifier: {}",
                            result.getLeft());
                    return Either.left(
                            MfaRetrieveFailureReason
                                    .UNEXPECTED_ERROR_CREATING_MFA_IDENTIFIER_FOR_NON_MIGRATED_AUTH_APP);
                }
            }
            return Either.right(
                    Optional.of(
                            MfaMethodData.authAppMfaData(
                                    mfaIdentifier,
                                    PriorityIdentifier.DEFAULT,
                                    method.isMethodVerified(),
                                    method.getCredentialValue())));
        } else if (userProfile.isPhoneNumberVerified()) {
            String mfaIdentifier;
            if (Objects.nonNull(userProfile.getMfaIdentifier())) {
                mfaIdentifier = userProfile.getMfaIdentifier();
            } else {
                mfaIdentifier = UUID.randomUUID().toString();
                persistentService.setMfaIdentifierForNonMigratedSmsMethod(
                        userProfile.getEmail(), mfaIdentifier);
            }
            return Either.right(
                    Optional.of(
                            MfaMethodData.smsMethodData(
                                    mfaIdentifier,
                                    PriorityIdentifier.DEFAULT,
                                    true,
                                    userProfile.getPhoneNumber())));
        } else {
            return Either.right(Optional.empty());
        }
    }

    public Result<MfaCreateFailureReason, MfaMethodData> addBackupMfa(
            String email, MfaMethodCreateOrUpdateRequest.MfaMethod mfaMethod) {
        if (mfaMethod.priorityIdentifier() == PriorityIdentifier.DEFAULT) {
            return Result.failure(MfaCreateFailureReason.INVALID_PRIORITY_IDENTIFIER);
        }

        UserCredentials userCredentials = persistentService.getUserCredentialsFromEmail(email);
        Either<MfaRetrieveFailureReason, List<MfaMethodData>> mfaMethodsResult =
                getMfaMethodsForMigratedUser(userCredentials);
        if (mfaMethodsResult.isLeft()) {
            return Result.failure(MfaCreateFailureReason.ERROR_RETRIEVING_MFA_METHODS);
        }

        var mfaMethods = mfaMethodsResult.get();

        if (mfaMethods.size() >= 2) {
            return Result.failure(MfaCreateFailureReason.BACKUP_AND_DEFAULT_METHOD_ALREADY_EXIST);
        }

        if (mfaMethod.method() instanceof SmsMfaDetail smsMfaDetail) {

            boolean phoneNumberExists =
                    mfaMethods.stream()
                            .map(MfaMethodData::method)
                            .filter(SmsMfaDetail.class::isInstance)
                            .map(SmsMfaDetail.class::cast)
                            .anyMatch(mfa -> mfa.phoneNumber().equals(smsMfaDetail.phoneNumber()));

            if (phoneNumberExists) {
                return Result.failure(MfaCreateFailureReason.PHONE_NUMBER_ALREADY_EXISTS);
            }

            String uuid = UUID.randomUUID().toString();
            persistentService.addMFAMethodSupportingMultiple(
                    email,
                    MFAMethod.smsMfaMethod(
                            true,
                            true,
                            smsMfaDetail.phoneNumber(),
                            mfaMethod.priorityIdentifier(),
                            uuid));
            return Result.success(
                    MfaMethodData.smsMethodData(
                            uuid,
                            mfaMethod.priorityIdentifier(),
                            true,
                            smsMfaDetail.phoneNumber()));
        } else {
            boolean authAppExists = // TODO: Should this logic change to only look for "enabled"
                    // auth apps?
                    mfaMethods.stream()
                            .map(MfaMethodData::method)
                            .filter(AuthAppMfaDetail.class::isInstance)
                            .anyMatch(mfa -> true);

            if (authAppExists) {
                return Result.failure(MfaCreateFailureReason.AUTH_APP_EXISTS);
            }

            String uuid = UUID.randomUUID().toString();
            persistentService.addMFAMethodSupportingMultiple(
                    email,
                    MFAMethod.authAppMfaMethod(
                            ((AuthAppMfaDetail) mfaMethod.method()).credential(),
                            true,
                            true,
                            mfaMethod.priorityIdentifier(),
                            uuid));
            return Result.success(
                    MfaMethodData.authAppMfaData(
                            uuid,
                            mfaMethod.priorityIdentifier(),
                            true,
                            ((AuthAppMfaDetail) mfaMethod.method()).credential()));
        }
    }

    public Either<MfaUpdateFailureReason, List<MfaMethodData>> updateMfaMethod(
            String email, String mfaIdentifier, MfaMethodCreateOrUpdateRequest request) {
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
                                return Either.<MfaUpdateFailureReason, List<MfaMethodData>>left(
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
                .orElse(Either.left(MfaUpdateFailureReason.UNKOWN_MFA_IDENTIFIER));
    }

    private Either<MfaUpdateFailureReason, List<MfaMethodData>> handleBackupMethodUpdate(
            MFAMethod backupMethod,
            MfaMethodCreateOrUpdateRequest.MfaMethod updatedMethod,
            String email,
            List<MFAMethod> allMethods) {
        if (updatedMethod.method() instanceof SmsMfaDetail updatedSmsDetail) {
            var changesPhoneNumber =
                    !updatedSmsDetail.phoneNumber().equals(backupMethod.getDestination());
            if (changesPhoneNumber) {
                return Either.left(
                        MfaUpdateFailureReason.ATTEMPT_TO_UPDATE_BACKUP_METHOD_PHONE_NUMBER);
            }
        } else {
            var authAppDetail = (AuthAppMfaDetail) updatedMethod.method();
            var changesAuthAppCredential =
                    !authAppDetail.credential().equals(backupMethod.getCredentialValue());
            if (changesAuthAppCredential) {
                return Either.left(
                        MfaUpdateFailureReason.ATTEMPT_TO_UPDATE_BACKUP_METHOD_AUTH_APP_CREDENTIAL);
            }
        }

        if (updatedMethod.priorityIdentifier().equals(BACKUP)) {
            return Either.left(MfaUpdateFailureReason.REQUEST_TO_UPDATE_MFA_METHOD_WITH_NO_CHANGE);
        }
        var maybeDefaultMethod =
                allMethods.stream()
                        .filter(m -> Objects.equals(m.getPriority(), DEFAULT.name()))
                        .findFirst();

        if (maybeDefaultMethod.isEmpty()) {
            return Either.left(
                    MfaUpdateFailureReason.ATTEMPT_TO_UPDATE_BACKUP_WITH_NO_DEFAULT_METHOD);
        }

        var defaultMethod = maybeDefaultMethod.get();
        var databaseUpdateResult =
                persistentService.updateAllMfaMethodsForUser(
                        email,
                        List.of(
                                defaultMethod.withPriority(BACKUP.name()),
                                backupMethod.withPriority(DEFAULT.name())));

        return updateMfaResultToMfaMethodData(databaseUpdateResult);
    }

    private Either<MfaUpdateFailureReason, List<MfaMethodData>> updateMfaResultToMfaMethodData(
            Either<String, List<MFAMethod>> updateResult) {
        Either<String, List<MfaMethodData>> returnedMfaMethods =
                updateResult.flatMap(
                        mfaMethods ->
                                Either.sequenceRight(
                                                io.vavr.collection.List.ofAll(mfaMethods.stream())
                                                        .map(MfaMethodData::from))
                                        .map(Value::toJavaList)
                                        .map(list -> list.stream().sorted().toList()));

        return returnedMfaMethods.mapLeft(
                errorString -> {
                    LOG.error(errorString);
                    return MfaUpdateFailureReason.UNEXPECTED_ERROR;
                });
    }

    private Either<MfaUpdateFailureReason, List<MfaMethodData>> handleDefaultMethodUpdate(
            MFAMethod defaultMethod,
            MfaMethodCreateOrUpdateRequest.MfaMethod updatedMethod,
            String email,
            String mfaIdentifier,
            List<MFAMethod> allMethodsForUser) {
        var requestedPriority = updatedMethod.priorityIdentifier();
        if (requestedPriority == BACKUP) {
            return Either.left(MfaUpdateFailureReason.CANNOT_CHANGE_PRIORITY_OF_DEFAULT_METHOD);
        }

        Either<String, List<MFAMethod>> databaseUpdateResult;

        if (updatedMethod.method() instanceof SmsMfaDetail updatedSmsDetail) {
            var isExistingDefaultPhoneNumber =
                    updatedSmsDetail.phoneNumber().equals(defaultMethod.getDestination());
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
                                            updatedSmsDetail
                                                    .phoneNumber()
                                                    .equals(mfaMethod.getDestination()));
            if (isExistingDefaultPhoneNumber) {
                return Either.left(
                        MfaUpdateFailureReason.REQUEST_TO_UPDATE_MFA_METHOD_WITH_NO_CHANGE);
            } else if (isExistingBackupPhoneNumber) {
                return Either.left(
                        MfaUpdateFailureReason.ATTEMPT_TO_UPDATE_PHONE_NUMBER_WITH_BACKUP_NUMBER);
            } else {
                databaseUpdateResult =
                        persistentService.updateMigratedMethodPhoneNumber(
                                email, updatedSmsDetail.phoneNumber(), mfaIdentifier);
            }
        } else {
            var authAppDetail = (AuthAppMfaDetail) updatedMethod.method();
            if (authAppDetail.credential().equals(defaultMethod.getCredentialValue())) {
                return Either.left(
                        MfaUpdateFailureReason.REQUEST_TO_UPDATE_MFA_METHOD_WITH_NO_CHANGE);
            } else {
                databaseUpdateResult =
                        persistentService.updateMigratedAuthAppCredential(
                                email, authAppDetail.credential(), mfaIdentifier);
            }
        }

        return updateMfaResultToMfaMethodData(databaseUpdateResult);
    }

    private boolean updateRequestChangesMethodType(
            String methodTypeFromExisting, MfaDetail updatedMethodDetail) {
        return updatedMethodDetail instanceof AuthAppMfaDetail
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

        if (nonMigratedRetrieveResult.isLeft()) {
            return Optional.of(MfaMigrationFailureReason.UNEXPECTED_ERROR_RETRIEVING_METHODS);
        }

        var maybeNonMigratedMfaMethod = nonMigratedRetrieveResult.get();

        // Bail if no MFA methods to migrate
        if (maybeNonMigratedMfaMethod.isEmpty()) {
            persistentService.setMfaMethodsMigrated(email, true);
            return Optional.empty();
        }

        var nonMigratedMfaMethod = maybeNonMigratedMfaMethod.get();

        String mfaIdentifier;
        if (Objects.isNull(nonMigratedMfaMethod.mfaIdentifier())) {
            mfaIdentifier = UUID.randomUUID().toString();
        } else {
            mfaIdentifier = nonMigratedMfaMethod.mfaIdentifier();
        }

        return nonMigratedMfaMethod.method() instanceof AuthAppMfaDetail
                ? migrateAuthAppToNewFormat(
                        email, (AuthAppMfaDetail) nonMigratedMfaMethod.method(), mfaIdentifier)
                : migrateSmsToNewFormat(
                        email, (SmsMfaDetail) nonMigratedMfaMethod.method(), mfaIdentifier);
    }

    private Optional<MfaMigrationFailureReason> migrateAuthAppToNewFormat(
            String email, AuthAppMfaDetail authAppMfaDetail, String identifier) {
        persistentService.overwriteMfaMethodToCredentialsAndDeleteProfilePhoneNumberForUser(
                email,
                MFAMethod.authAppMfaMethod(
                        authAppMfaDetail.credential(),
                        true,
                        true,
                        PriorityIdentifier.DEFAULT,
                        identifier));
        return Optional.empty();
    }

    private Optional<MfaMigrationFailureReason> migrateSmsToNewFormat(
            String email, SmsMfaDetail smsMfaDetail, String identifier) {
        persistentService.overwriteMfaMethodToCredentialsAndDeleteProfilePhoneNumberForUser(
                email,
                MFAMethod.smsMfaMethod(
                        true,
                        true,
                        smsMfaDetail.phoneNumber(),
                        PriorityIdentifier.DEFAULT,
                        identifier));

        return Optional.empty();
    }
}
