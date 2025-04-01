package uk.gov.di.authentication.shared.services.mfa;

import io.vavr.Value;
import io.vavr.control.Either;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.AuthAppMfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.MfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.MfaMethodCreateOrUpdateRequest;
import uk.gov.di.authentication.shared.entity.mfa.MfaMethodData;
import uk.gov.di.authentication.shared.entity.mfa.SmsMfaDetail;
import uk.gov.di.authentication.shared.exceptions.UnknownMfaTypeException;
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

public class MfaMethodsService {
    private static final Logger LOG = LogManager.getLogger(MfaMethodsService.class);

    private final AuthenticationService persistentService;

    // TODO generate and store UUID (AUT-4122)
    public static final String HARDCODED_APP_MFA_ID = "f2ec40f3-9e63-496c-a0a5-a3bdafee868b";
    public static final String HARDCODED_SMS_MFA_ID = "35c7940d-be5f-4b31-95b7-0eedc42929b9";

    public MfaMethodsService(ConfigurationService configurationService) {
        this.persistentService = new DynamoService(configurationService);
    }

    public List<MfaMethodData> getMfaMethods(String email) {
        var userProfile = persistentService.getUserProfileByEmail(email);
        var userCredentials = persistentService.getUserCredentialsFromEmail(email);
        if (Boolean.TRUE.equals(userProfile.getMfaMethodsMigrated())) {
            return getMfaMethodsForMigratedUser(userCredentials);
        } else {
            return getMfaMethodForNonMigratedUser(userProfile, userCredentials)
                    .map(List::of)
                    .orElseGet(List::of);
        }
    }

    private List<MfaMethodData> getMfaMethodsForMigratedUser(UserCredentials userCredentials)
            throws UnknownMfaTypeException {
        return Optional.ofNullable(userCredentials.getMfaMethods())
                .orElse(new ArrayList<>())
                .stream()
                .map(
                        mfaMethod -> {
                            if (mfaMethod
                                    .getMfaMethodType()
                                    .equals(MFAMethodType.AUTH_APP.getValue())) {
                                return MfaMethodData.authAppMfaData(
                                        mfaMethod.getMfaIdentifier(),
                                        PriorityIdentifier.valueOf(mfaMethod.getPriority()),
                                        mfaMethod.isMethodVerified(),
                                        mfaMethod.getCredentialValue());
                            } else if (mfaMethod
                                    .getMfaMethodType()
                                    .equals(MFAMethodType.SMS.getValue())) {
                                return MfaMethodData.smsMethodData(
                                        mfaMethod.getMfaIdentifier(),
                                        PriorityIdentifier.valueOf(mfaMethod.getPriority()),
                                        mfaMethod.isMethodVerified(),
                                        mfaMethod.getDestination());
                            } else {
                                LOG.error(
                                        "Unknown mfa method type: {}",
                                        mfaMethod.getMfaMethodType());
                                throw new UnknownMfaTypeException(
                                        "Unknown mfa method type: " + mfaMethod.getMfaMethodType());
                            }
                        })
                .toList();
    }

    public Either<MfaDeleteFailureReason, String> deleteMfaMethod(
            String publicSubjectId, String mfaIdentifier) {
        var maybeUserProfile =
                persistentService.getOptionalUserProfileFromPublicSubject(publicSubjectId);

        if (maybeUserProfile.isEmpty()) {
            return Either.left(MfaDeleteFailureReason.NO_USER_PROFILE_FOUND_FOR_PUBLIC_SUBJECT_ID);
        }
        var userProfile = maybeUserProfile.get();
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

    private Optional<MfaMethodData> getMfaMethodForNonMigratedUser(
            UserProfile userProfile, UserCredentials userCredentials) {
        var enabledAuthAppMethod = getPrimaryMFAMethod(userCredentials);
        if (enabledAuthAppMethod.isPresent()) {
            var method = enabledAuthAppMethod.get();
            return Optional.of(
                    MfaMethodData.authAppMfaData(
                            HARDCODED_APP_MFA_ID,
                            PriorityIdentifier.DEFAULT,
                            method.isMethodVerified(),
                            method.getCredentialValue()));
        } else if (userProfile.isPhoneNumberVerified()) {
            return Optional.of(
                    MfaMethodData.smsMethodData(
                            HARDCODED_SMS_MFA_ID,
                            PriorityIdentifier.DEFAULT,
                            true,
                            userProfile.getPhoneNumber()));
        } else {
            return Optional.empty();
        }
    }

    public Either<MfaCreateFailureReason, MfaMethodData> addBackupMfa(
            String email, MfaMethodCreateOrUpdateRequest.MfaMethod mfaMethod) {
        if (mfaMethod.priorityIdentifier() == PriorityIdentifier.DEFAULT) {
            return Either.left(MfaCreateFailureReason.INVALID_PRIORITY_IDENTIFIER);
        }

        UserCredentials userCredentials = persistentService.getUserCredentialsFromEmail(email);
        List<MfaMethodData> mfaMethods = getMfaMethodsForMigratedUser(userCredentials);

        if (mfaMethods.size() >= 2) {
            return Either.left(MfaCreateFailureReason.BACKUP_AND_DEFAULT_METHOD_ALREADY_EXIST);
        }

        if (mfaMethod.method() instanceof SmsMfaDetail smsMfaDetail) {

            boolean phoneNumberExists =
                    mfaMethods.stream()
                            .map(MfaMethodData::method)
                            .filter(SmsMfaDetail.class::isInstance)
                            .map(SmsMfaDetail.class::cast)
                            .anyMatch(mfa -> mfa.phoneNumber().equals(smsMfaDetail.phoneNumber()));

            if (phoneNumberExists) {
                return Either.left(MfaCreateFailureReason.PHONE_NUMBER_ALREADY_EXISTS);
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
            return Either.right(
                    MfaMethodData.smsMethodData(
                            uuid,
                            mfaMethod.priorityIdentifier(),
                            true,
                            smsMfaDetail.phoneNumber()));
        } else {
            boolean authAppExists =
                    mfaMethods.stream()
                            .map(MfaMethodData::method)
                            .filter(AuthAppMfaDetail.class::isInstance)
                            .anyMatch(mfa -> true);

            if (authAppExists) {
                return Either.left(MfaCreateFailureReason.AUTH_APP_EXISTS);
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
            return Either.right(
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
        if (maybeUserProfile.isEmpty() || maybeUserCredentials.isEmpty())
            return Optional.of(MfaMigrationFailureReason.NO_USER_FOUND_FOR_EMAIL);

        UserProfile userProfile = maybeUserProfile.get();
        UserCredentials userCredentials = maybeUserCredentials.get();

        // Bail if already migrated
        if (userProfile.getMfaMethodsMigrated())
            return Optional.of(MfaMigrationFailureReason.ALREADY_MIGRATED);

        // TODO - AUT-2198 - This method obfuscates things a bit
        //  It includes only enabled UserCredentials and verified phone numbers. What should we do
        // if they aren't either of these?
        var maybeNonMigratedMfaMethod =
                getMfaMethodForNonMigratedUser(userProfile, userCredentials);

        // Bail if no MFA methods to migrate
        if (maybeNonMigratedMfaMethod.isEmpty()) {
            persistentService.setMfaMethodsMigrated(email, true);
            return Optional.empty();
            // TODO - AUT-2198 - By doing this, we need to make sure that all new MFA methods are
            // getting added the new way before running before running a bulk migration, otherwise
            // we could end up with a situation where we think something is migrated but actually
            // isn't.
            // TODO - AUT-2198 - Maybe we shouldn't do this given the two TODOs below
        }

        var nonMigratedMfaMethod = maybeNonMigratedMfaMethod.get();

        return nonMigratedMfaMethod.method() instanceof AuthAppMfaDetail
                ? migrateAuthAppToNewFormat(
                        email,
                        nonMigratedMfaMethod) // TODO - AUT-2198 - What should do for non-enabled
                // auth app?
                : migrateSmsToNewFormat(
                        email,
                        nonMigratedMfaMethod,
                        userProfile); // TODO - AUT-2198 - What should do for non-verified phone?
    }

    private Optional<MfaMigrationFailureReason> migrateAuthAppToNewFormat(
            String email, MfaMethodData mfaMethodData) {
        var method = (AuthAppMfaDetail) mfaMethodData.method();
        persistentService.migrateMfaMethodsToCredentialsTableForUser(
                email,
                MFAMethod.authAppMfaMethod(
                        method.credential(),
                        true,
                        true,
                        mfaMethodData.priorityIdentifier(),
                        UUID.randomUUID().toString()));
        return Optional.empty();
    }

    private Optional<MfaMigrationFailureReason> migrateSmsToNewFormat(
            String email, MfaMethodData mfaMethodData, UserProfile userProfile) {
        var method = (SmsMfaDetail) mfaMethodData.method();

        // Bail if phoneNumber isn't verified
        if (!userProfile.isPhoneNumberVerified())
            return Optional.of(MfaMigrationFailureReason.PHONE_NUMBER_NOT_VERIFIED);

        persistentService.migrateMfaMethodsToCredentialsTableForUser(
                email,
                MFAMethod.smsMfaMethod(
                        true,
                        true,
                        method.phoneNumber(),
                        PriorityIdentifier.DEFAULT,
                        UUID.randomUUID().toString()));

        return Optional.empty();
    }
}
