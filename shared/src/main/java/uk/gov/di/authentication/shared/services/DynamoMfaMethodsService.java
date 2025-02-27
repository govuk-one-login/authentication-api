package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.*;

import java.util.List;

import static uk.gov.di.authentication.shared.conditions.MfaHelper.getPrimaryMFAMethod;

public class DynamoMfaMethodsService implements MfaMethodsService {

    private final DynamoService dynamoService;

    public DynamoMfaMethodsService(ConfigurationService configurationService) {
        this.dynamoService = new DynamoService(configurationService);
    }

    @Override
    public List<MfaData> getMfaMethods(String email) {
        var userProfile = dynamoService.getUserProfileByEmail(email);
        var userCredentials = dynamoService.getUserCredentialsFromEmail(email);
        var enabledAuthAppMethod = getPrimaryMFAMethod(userCredentials);
        if (enabledAuthAppMethod.isPresent()) {
            return List.of(convertAuthAppToAuthAppMfaData(enabledAuthAppMethod.get()));
        } else if (userProfile.isPhoneNumberVerified()) {
            return List.of(getSmsMfaDataFromUserProfile(userProfile));
        } else {
            return List.of();
        }
    }

    private static AuthAppMfaData convertAuthAppToAuthAppMfaData(MFAMethod authApp) {
        return new AuthAppMfaData(
                authApp.getCredentialValue(),
                authApp.isMethodVerified(),
                true,
                PriorityIdentifier.DEFAULT,
                1);
    }

    // TODO how to get identifier?
    private static SmsMfaData getSmsMfaDataFromUserProfile(UserProfile userProfile) {
        return new SmsMfaData(
                userProfile.getPhoneNumber(),
                userProfile.isPhoneNumberVerified(),
                true,
                PriorityIdentifier.DEFAULT,
                1);
    }
}
