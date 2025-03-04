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
    public List<MfaMethodData> getMfaMethods(String email) {
        var userProfile = dynamoService.getUserProfileByEmail(email);
        var userCredentials = dynamoService.getUserCredentialsFromEmail(email);
        var enabledAuthAppMethod = getPrimaryMFAMethod(userCredentials);
        // TODO how to get identifier?
        if (enabledAuthAppMethod.isPresent()) {
            var method = enabledAuthAppMethod.get();
            return List.of(
                    MfaMethodData.authAppMfaData(
                            1,
                            PriorityIdentifier.DEFAULT,
                            method.isMethodVerified(),
                            method.getCredentialValue()));
        } else if (userProfile.isPhoneNumberVerified()) {
            return List.of(
                    MfaMethodData.smsMethodData(
                            1, PriorityIdentifier.DEFAULT, true, userProfile.getPhoneNumber()));
        } else {
            return List.of();
        }
    }
}
