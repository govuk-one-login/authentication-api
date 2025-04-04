package uk.gov.di.accountmanagement.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.services.AuthenticationService;

import java.util.Map;

public class PrincipalValidationHelper {

    private static final Logger LOG = LogManager.getLogger(PrincipalValidationHelper.class);
    private static final String PRINCIPAL_ID_KEY = "principalId";

    private PrincipalValidationHelper() {}

    public static boolean principalIsInvalid(
            UserProfile userProfile,
            String internalSectorUri,
            AuthenticationService authenticationService,
            Map<String, Object> authorizerParams) {
        if (!authorizerParams.containsKey(PRINCIPAL_ID_KEY)) {
            LOG.warn("principalId is missing");
            return true;
        } else {
            LOG.info("Validating principalId against internal pairwise subject id");
            var internalSubjectId =
                    ClientSubjectHelper.getSubjectWithSectorIdentifier(
                            userProfile, internalSectorUri, authenticationService);
            return !internalSubjectId.getValue().equals(authorizerParams.get(PRINCIPAL_ID_KEY));
        }
    }
}
