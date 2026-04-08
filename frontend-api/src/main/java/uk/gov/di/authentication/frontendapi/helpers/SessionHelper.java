package uk.gov.di.authentication.frontendapi.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.lambda.VerifyMfaCodeHandler;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;

public class SessionHelper {
    private static final Logger LOG = LogManager.getLogger(VerifyMfaCodeHandler.class);

    public static void updateSessionWithSubject(
            UserContext userContext,
            AuthSessionService authSessionService,
            AuthenticationService authenticationService,
            ConfigurationService configurationService) {
        LOG.info("Calculating internal common subject identifier");
        var authSession = userContext.getAuthSession();
        UserProfile userProfile =
                userContext.getUserProfile().isPresent()
                        ? userContext.getUserProfile().get()
                        : authenticationService.getUserProfileByEmail(
                                authSession.getEmailAddress());
        var internalCommonSubjectId =
                authSession.getInternalCommonSubjectId() != null
                        ? authSession.getInternalCommonSubjectId()
                        : ClientSubjectHelper.getSubjectWithSectorIdentifier(
                                        userProfile,
                                        configurationService.getInternalSectorUri(),
                                        authenticationService)
                                .getValue();
        LOG.info("Setting internal common subject identifier in user session");
        authSession.setInternalCommonSubjectId(internalCommonSubjectId);
        authSessionService.updateSession(authSession);
    }
}
