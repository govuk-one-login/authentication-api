package uk.gov.di.orchestration.shared.services;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.audit.AuditContext;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.entity.AccountIntervention;
import uk.gov.di.orchestration.shared.entity.DestroySessionsRequest;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;

import java.util.Map;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.entity.AccountInterventionStatus.SUSPENDED_REPROVE_ID;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class EndOfJourneyService {

    private static final Logger LOG = LogManager.getLogger(EndOfJourneyService.class);
    private final ConfigurationService configurationService;
    private final AccountInterventionService accountInterventionService;
    private final LogoutService logoutService;
    private final OrchAuthCodeService orchAuthCodeService;

    public EndOfJourneyService(
            ConfigurationService configurationService,
            AccountInterventionService accountInterventionService,
            LogoutService logoutService,
            OrchAuthCodeService orchAuthCodeService) {
        this.configurationService = configurationService;
        this.accountInterventionService = accountInterventionService;
        this.logoutService = logoutService;
        this.orchAuthCodeService = orchAuthCodeService;
    }

    public AccountIntervention getIntervention(
            String internalCommonSubjectId, AuditContext auditContext) {
        return segmentedFunctionCall(
                "AIS: getAccountIntervention",
                () ->
                        accountInterventionService.getAccountIntervention(
                                internalCommonSubjectId, auditContext));
    }

    public Optional<APIGatewayProxyResponseEvent> getAndCheckForIntervention(
            OrchSessionItem orchSession,
            AuditContext auditContext,
            TxmaAuditUser auditUser,
            String clientId,
            boolean isAuthJourney) {
        return checkForIntervention(
                orchSession,
                getIntervention(orchSession.getInternalCommonSubjectId(), auditContext),
                auditUser,
                clientId,
                isAuthJourney);
    }

    public Optional<APIGatewayProxyResponseEvent> checkForIntervention(
            OrchSessionItem orchSession,
            AccountIntervention intervention,
            TxmaAuditUser auditUser,
            String clientId,
            boolean isAuthJourney) {
        if (configurationService.isAccountInterventionServiceActionEnabled()) {
            if (isAuthJourney && SUSPENDED_REPROVE_ID.equals(intervention.getStatus())) {
                return Optional.empty();
            }
            if (intervention.getBlocked() || intervention.getSuspended()) {
                return Optional.of(
                        logoutService.handleAccountInterventionLogout(
                                new DestroySessionsRequest(orchSession.getSessionId(), orchSession),
                                auditUser,
                                clientId,
                                intervention));
            }
        }
        return Optional.empty();
    }

    public AuthenticationSuccessResponse generateSuccessfulAuthResponse(
            AuthenticationRequest authRequest,
            String clientId,
            String clientSessionId,
            String email,
            OrchSessionItem orchSession) {
        var authCode =
                orchAuthCodeService.generateAndSaveAuthorisationCode(
                        clientId,
                        clientSessionId,
                        email,
                        orchSession.getAuthTime(),
                        orchSession.getInternalCommonSubjectId());
        return new AuthenticationSuccessResponse(
                authRequest.getRedirectionURI(),
                authCode,
                null,
                null,
                authRequest.getState(),
                null,
                authRequest.getResponseMode());
    }

    public APIGatewayProxyResponseEvent generateAuthenticationErrorResponse(
            AuthenticationRequest authenticationRequest, ErrorObject error) {
        LOG.warn(
                "Error in Authorisation Response. ErrorCode: {}. ErrorDescription: {}.",
                error.getCode(),
                error.getDescription());
        var errorResponseUri =
                new AuthenticationErrorResponse(
                                authenticationRequest.getRedirectionURI(),
                                error,
                                authenticationRequest.getState(),
                                authenticationRequest.getResponseMode())
                        .toURI();

        return generateApiGatewayProxyResponse(
                302, "", Map.of(ResponseHeaders.LOCATION, errorResponseUri.toString()), null);
    }
}
