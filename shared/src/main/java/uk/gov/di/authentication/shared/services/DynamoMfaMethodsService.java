package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.*;

import java.util.List;

import static uk.gov.di.authentication.shared.conditions.MfaHelper.getPrimaryMFAMethod;

public class DynamoMfaMethodsService implements MfaMethodsService {

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
}
