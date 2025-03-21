package uk.gov.di.authentication.shared.services.mfa;

import io.vavr.control.Either;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.*;
import uk.gov.di.authentication.shared.entity.mfa.AuthAppMfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.MfaMethodCreateRequest;
import uk.gov.di.authentication.shared.entity.mfa.MfaMethodData;
import uk.gov.di.authentication.shared.entity.mfa.SmsMfaDetail;
import uk.gov.di.authentication.shared.exceptions.UnknownMfaTypeException;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.util.List;
import java.util.UUID;

import static uk.gov.di.authentication.shared.conditions.MfaHelper.getPrimaryMFAMethod;

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
            return getMfaMethodsForNonMigratedUser(userProfile, userCredentials);
        }
    }

    private List<MfaMethodData> getMfaMethodsForMigratedUser(UserCredentials userCredentials)
            throws UnknownMfaTypeException {
        return userCredentials.getMfaMethods().stream()
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

        if (!PriorityIdentifier.BACKUP.name().equals(maybeMethodToDelete.get().getPriority())) {
            return Either.left(MfaDeleteFailureReason.CANNOT_DELETE_DEFAULT_METHOD);
        }

        persistentService.deleteMfaMethodByIdentifier(userProfile.getEmail(), mfaIdentifier);
        return Either.right(mfaIdentifier);
    }

    private List<MfaMethodData> getMfaMethodsForNonMigratedUser(
            UserProfile userProfile, UserCredentials userCredentials) {
        var enabledAuthAppMethod = getPrimaryMFAMethod(userCredentials);
        if (enabledAuthAppMethod.isPresent()) {
            var method = enabledAuthAppMethod.get();
            return List.of(
                    MfaMethodData.authAppMfaData(
                            HARDCODED_APP_MFA_ID,
                            PriorityIdentifier.DEFAULT,
                            method.isMethodVerified(),
                            method.getCredentialValue()));
        } else if (userProfile.isPhoneNumberVerified()) {
            return List.of(
                    MfaMethodData.smsMethodData(
                            HARDCODED_SMS_MFA_ID,
                            PriorityIdentifier.DEFAULT,
                            true,
                            userProfile.getPhoneNumber()));
        } else {
            return List.of();
        }
    }

    public Either<MfaCreateFailureReason, MfaMethodData> addBackupMfa(
            String email, MfaMethodCreateRequest.MfaMethod mfaMethod) {
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
}
