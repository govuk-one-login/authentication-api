package uk.gov.di.authentication.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.entity.MfaMethodCreateRequest;
import uk.gov.di.authentication.shared.entity.*;
import uk.gov.di.authentication.shared.exceptions.InvalidPriorityIdentifierException;
import uk.gov.di.authentication.shared.exceptions.UnknownMfaTypeException;

import java.util.List;
import java.util.UUID;

import static uk.gov.di.authentication.shared.conditions.MfaHelper.getPrimaryMFAMethod;

public class DynamoMfaMethodsService implements MfaMethodsService {
    private static final Logger LOG = LogManager.getLogger(DynamoMfaMethodsService.class);

    private final DynamoService dynamoService;

    // TODO generate and store UUID (AUT-4122)
    public static final String HARDCODED_APP_MFA_ID = "f2ec40f3-9e63-496c-a0a5-a3bdafee868b";
    public static final String HARDCODED_SMS_MFA_ID = "35c7940d-be5f-4b31-95b7-0eedc42929b9";

    public DynamoMfaMethodsService(ConfigurationService configurationService) {
        this.dynamoService = new DynamoService(configurationService);
    }

    @Override
    public List<MfaMethodData> getMfaMethods(String email) {
        var userProfile = dynamoService.getUserProfileByEmail(email);
        var userCredentials = dynamoService.getUserCredentialsFromEmail(email);
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

    public void deleteMfaMethod(String email, String mfaIdentifier) {
        dynamoService.deleteMfaMethodByIdentifier(email, mfaIdentifier);
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

    @Override
    public MfaMethodData addBackupMfa(String email, MfaMethodCreateRequest.MfaMethod mfaMethod)
            throws InvalidPriorityIdentifierException {
        if (mfaMethod.priorityIdentifier() == PriorityIdentifier.DEFAULT) {
            throw new InvalidPriorityIdentifierException(
                    "Priority identifier for newly added MFA method should be BACKUP");
        }

        if (mfaMethod.method() instanceof SmsMfaDetail smsMfaDetail) {
            String uuid = UUID.randomUUID().toString();
            dynamoService.addMFAMethodSupportingMultiple(
                    email,
                    new SmsMfaData(
                            smsMfaDetail.phoneNumber(),
                            true,
                            true,
                            mfaMethod.priorityIdentifier(),
                            uuid));
            return MfaMethodData.smsMethodData(
                    uuid, mfaMethod.priorityIdentifier(), true, smsMfaDetail.phoneNumber());
        }

        //      Further implementation to come in subsequent commits
        return null;
    }
}
