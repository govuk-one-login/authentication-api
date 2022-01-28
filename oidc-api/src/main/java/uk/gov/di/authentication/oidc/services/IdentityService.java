package uk.gov.di.authentication.oidc.services;

import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import uk.gov.di.authentication.oidc.entity.AccessTokenInfo;
import uk.gov.di.authentication.oidc.entity.IdentityResponse;
import uk.gov.di.authentication.shared.entity.SPOTCredential;
import uk.gov.di.authentication.shared.exceptions.AccessTokenException;
import uk.gov.di.authentication.shared.services.DynamoSpotService;

import java.util.Optional;

public class IdentityService {

    private final DynamoSpotService spotService;

    public IdentityService(DynamoSpotService spotService) {
        this.spotService = spotService;
    }

    public IdentityResponse populateIdentityResponse(AccessTokenInfo accessTokenInfo)
            throws AccessTokenException {
        Optional<SPOTCredential> spotCredential =
                spotService.getSpotCredential(accessTokenInfo.getPublicSubject());
        if (spotCredential.isEmpty()) {
            throw new AccessTokenException("Invalid Access Token", BearerTokenError.INVALID_TOKEN);
        }
        return new IdentityResponse(
                spotCredential.get().getSubjectID(),
                spotCredential.get().getSerializedCredential());
    }
}
