package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.*;

import java.util.List;

public class DynamoMfaMethodsService implements MfaMethodsService {

    private final DynamoService dynamoService;

    public DynamoMfaMethodsService(ConfigurationService configurationService) {
        this.dynamoService = new DynamoService(configurationService);
    }

    @Override
    public List<MfaData> getMfaMethods(String email) {
        var userProfile = dynamoService.getUserProfileByEmail(email);
        if (userProfile.isPhoneNumberVerified()) {
            // TODO how to get identifier?
            return List.of(
                    new SmsMfaData(
                            userProfile.getPhoneNumber(),
                            userProfile.isPhoneNumberVerified(),
                            true,
                            PriorityIdentifier.DEFAULT,
                            1));
        } else {
            return List.of();
        }
    }
}
