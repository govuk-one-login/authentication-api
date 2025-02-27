package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.*;

import java.util.List;

public class MfaMethodsDynamoService implements MfaMethodsService {

    private final DynamoService dynamoService;

    public MfaMethodsDynamoService(ConfigurationService configurationService) {
        this.dynamoService = new DynamoService(configurationService);
    }

    @Override
    public List<MfaData> getMfaMethods(String email) {
        var userProfile = dynamoService.getUserProfileByEmail(email);
        if (userProfile.isPhoneNumberVerified()) {
            // TODO how to get identifier?
            // TODO: is this always enabled? What if someone switches from phone to auth app?
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
