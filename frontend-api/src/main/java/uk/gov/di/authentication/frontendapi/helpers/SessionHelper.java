package uk.gov.di.authentication.frontendapi.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.lambda.VerifyMfaCodeHandler;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

public class SessionHelper {
    private static final Logger LOG = LogManager.getLogger(VerifyMfaCodeHandler.class);

    public static void updateSessionWithSubject(
            UserContext userContext,
            AuthenticationService authenticationService,
            ConfigurationService configurationService,
            SessionService sessionService,
            Session session) {
        LOG.info("Calculating internal common subject identifier");
        UserProfile userProfile =
                userContext.getUserProfile().isPresent()
                        ? userContext.getUserProfile().get()
                        : authenticationService.getUserProfileByEmail(session.getEmailAddress());
        var internalCommonSubjectIdentifier =
                session.getInternalCommonSubjectIdentifier() != null
                        ? session.getInternalCommonSubjectIdentifier()
                        : ClientSubjectHelper.getSubjectWithSectorIdentifier(
                                        userProfile,
                                        configurationService.getInternalSectorUri(),
                                        authenticationService)
                                .getValue();
        LOG.info("Setting internal common subject identifier in user session");
        sessionService.save(
                userContext
                        .getSession()
                        .setInternalCommonSubjectIdentifier(internalCommonSubjectIdentifier));
    }
}
