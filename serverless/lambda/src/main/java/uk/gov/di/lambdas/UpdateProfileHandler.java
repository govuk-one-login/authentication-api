package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.domain.AccountManagementAuditableEvent;
import uk.gov.di.entity.BaseAPIResponse;
import uk.gov.di.entity.ClientConsent;
import uk.gov.di.entity.ClientSession;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.entity.Session;
import uk.gov.di.entity.UpdateProfileRequest;
import uk.gov.di.entity.ValidScopes;
import uk.gov.di.helpers.StateMachine.InvalidStateTransitionException;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.ClientSessionService;
import uk.gov.di.services.DynamoService;
import uk.gov.di.services.SessionService;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Set;

import static uk.gov.di.entity.SessionState.ADDED_CONSENT;
import static uk.gov.di.entity.SessionState.ADDED_UNVERIFIED_PHONE_NUMBER;
import static uk.gov.di.entity.SessionState.UPDATED_TERMS_AND_CONDITIONS;
import static uk.gov.di.entity.UpdateProfileType.UPDATE_TERMS_CONDS;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.helpers.StateMachine.validateStateTransition;

public class UpdateProfileHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(UpdateProfileHandler.class);

    private final AuthenticationService authenticationService;
    private final SessionService sessionService;
    private final ClientSessionService clientSessionService;
    private final ConfigurationService configurationService;
    private final AuditService auditService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public UpdateProfileHandler(
            AuthenticationService authenticationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ConfigurationService configurationService,
            AuditService auditService) {
        this.authenticationService = authenticationService;
        this.sessionService = sessionService;
        this.clientSessionService = clientSessionService;
        this.configurationService = configurationService;
        this.auditService = auditService;
    }

    public UpdateProfileHandler() {
        configurationService = new ConfigurationService();
        this.authenticationService =
                new DynamoService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
        sessionService = new SessionService(configurationService);
        clientSessionService = new ClientSessionService(configurationService);
        auditService = new AuditService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        auditService.submitAuditEvent(
                AccountManagementAuditableEvent.ACCOUNT_MANAGEMENT_REQUEST_RECEIVED);

        Optional<Session> session = sessionService.getSessionFromRequestHeaders(input.getHeaders());
        String clientId;

        if (session.isEmpty()) {
            LOGGER.info("Session is empty.");
            return generateErrorResponse(ErrorResponse.ERROR_1000);
        }
        try {
            UpdateProfileRequest profileRequest =
                    objectMapper.readValue(input.getBody(), UpdateProfileRequest.class);
            if (!session.get().validateSession(profileRequest.getEmail())) {
                LOGGER.info("Invalid session. Email {}", profileRequest.getEmail());
                return generateErrorResponse(ErrorResponse.ERROR_1000);
            }
            switch (profileRequest.getUpdateProfileType()) {
                case ADD_PHONE_NUMBER:
                    {
                        validateStateTransition(session.get(), ADDED_UNVERIFIED_PHONE_NUMBER);
                        authenticationService.updatePhoneNumber(
                                profileRequest.getEmail(), profileRequest.getProfileInformation());
                        auditService.submitAuditEvent(
                                AccountManagementAuditableEvent
                                        .ACCOUNT_MANAGEMENT_PHONE_NUMBER_UPDATED);
                        sessionService.save(session.get().setState(ADDED_UNVERIFIED_PHONE_NUMBER));
                        LOGGER.info(
                                "Phone number updated and session state changed. Session state {}",
                                ADDED_UNVERIFIED_PHONE_NUMBER);
                        return generateApiGatewayProxyResponse(
                                200, new BaseAPIResponse(session.get().getState()));
                    }
                case CAPTURE_CONSENT:
                    {
                        Optional<ClientSession> clientSession =
                                clientSessionService.getClientSessionFromRequestHeaders(
                                        input.getHeaders());

                        if (clientSession.isEmpty()) {
                            LOGGER.info("ClientSession not found.");
                            return generateErrorResponse(ErrorResponse.ERROR_1000);
                        }
                        AuthenticationRequest authorizationRequest;
                        try {
                            authorizationRequest =
                                    AuthenticationRequest.parse(
                                            clientSession.get().getAuthRequestParams());
                            clientId = authorizationRequest.getClientID().getValue();
                        } catch (ParseException e) {
                            LOGGER.info(
                                    "Cannot retrieve auth request params from client session id.");
                            return generateErrorResponse(ErrorResponse.ERROR_1001);
                        }
                        Set<String> claims =
                                ValidScopes.getClaimsForListOfScopes(
                                        authorizationRequest.getScope().toStringList());

                        Optional<ClientConsent> clientConsentForClientId =
                                authenticationService
                                        .getUserConsents(profileRequest.getEmail())
                                        .flatMap(
                                                list ->
                                                        list.stream()
                                                                .filter(
                                                                        c ->
                                                                                c.getClientId()
                                                                                        .equals(
                                                                                                clientId))
                                                                .findFirst());

                        ClientConsent clientConsentToUpdate =
                                clientConsentForClientId
                                        .map(t -> t.setClaims(claims))
                                        .orElse(
                                                new ClientConsent(
                                                        clientId,
                                                        claims,
                                                        LocalDateTime.now().toString()));

                        LOGGER.info(
                                "Consent value successfully added to ClientConsentObject. Attempting to update UserProfile with ClientConsent: {}",
                                clientConsentToUpdate);

                        authenticationService.updateConsent(
                                profileRequest.getEmail(), clientConsentToUpdate);

                        auditService.submitAuditEvent(
                                AccountManagementAuditableEvent.ACCOUNT_MANAGEMENT_CONSENT_UPDATED);

                        sessionService.save(session.get().setState(ADDED_CONSENT));

                        LOGGER.info(
                                "Consent updated for ClientID {} and session state changed. Session state {}",
                                clientId,
                                ADDED_CONSENT);

                        return generateApiGatewayProxyResponse(
                                200, new BaseAPIResponse(session.get().getState()));
                    }
                case UPDATE_TERMS_CONDS:
                    {
                        authenticationService.updateTermsAndConditions(
                                profileRequest.getEmail(),
                                configurationService.getTermsAndConditionsVersion());

                        auditService.submitAuditEvent(
                                AccountManagementAuditableEvent
                                        .ACCOUNT_MANAGEMENT_TERMS_CONDS_ACCEPTANCE_UPDATED);
                        LOGGER.info(
                                "Updated terms and conditions. Email {} for Version {}",
                                profileRequest.getEmail(),
                                configurationService.getTermsAndConditionsVersion());

                        sessionService.save(session.get().setState(UPDATED_TERMS_AND_CONDITIONS));

                        LOGGER.info(
                                "Updated terms and conditions. Session state {}",
                                UPDATE_TERMS_CONDS);

                        return generateApiGatewayProxyResponse(
                                200, new BaseAPIResponse(session.get().getState()));
                    }
            }
        } catch (JsonProcessingException e) {
            LOGGER.info("JsonProcessingException", e);
            return generateErrorResponse(ErrorResponse.ERROR_1001);
        } catch (InvalidStateTransitionException e) {
            return generateErrorResponse(ErrorResponse.ERROR_1017);
        }
        return generateErrorResponse(ErrorResponse.ERROR_1013);
    }

    private APIGatewayProxyResponseEvent generateErrorResponse(ErrorResponse errorResponse) {
        auditService.submitAuditEvent(
                AccountManagementAuditableEvent.ACCOUNT_MANAGEMENT_REQUEST_ERROR);
        return generateApiGatewayProxyErrorResponse(400, errorResponse);
    }
}
