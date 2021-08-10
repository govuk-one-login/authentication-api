package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.entity.BaseAPIResponse;
import uk.gov.di.entity.ClientSession;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.entity.Session;
import uk.gov.di.entity.UpdateProfileRequest;
import uk.gov.di.helpers.CookieHelper;
import uk.gov.di.helpers.StateMachine.InvalidStateTransitionException;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.ClientSessionService;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.DynamoService;
import uk.gov.di.services.SessionService;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.entity.SessionState.ADDED_CONSENT;
import static uk.gov.di.entity.SessionState.ADDED_UNVERIFIED_PHONE_NUMBER;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.helpers.StateMachine.validateStateTransition;

public class UpdateProfileHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(UpdateProfileHandler.class);

    private final AuthenticationService authenticationService;
    private final SessionService sessionService;
    private final ClientSessionService clientSessionService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public UpdateProfileHandler(
            AuthenticationService authenticationService,
            SessionService sessionService,
            ClientSessionService clientSessionService) {
        this.authenticationService = authenticationService;
        this.sessionService = sessionService;
        this.clientSessionService = clientSessionService;
    }

    public UpdateProfileHandler() {
        ConfigurationService configurationService = new ConfigurationService();
        this.authenticationService =
                new DynamoService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
        sessionService = new SessionService(configurationService);
        clientSessionService = new ClientSessionService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        Optional<Session> session = sessionService.getSessionFromRequestHeaders(input.getHeaders());
        CookieHelper.SessionCookieIds sessionCookieIds;
        String clientId;

        if (session.isEmpty()) {
            LOGGER.info("Session is empty.");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
        }
        try {
            UpdateProfileRequest profileRequest =
                    objectMapper.readValue(input.getBody(), UpdateProfileRequest.class);
            if (!session.get().validateSession(profileRequest.getEmail())) {
                LOGGER.info("Invalid session. Email {}", profileRequest.getEmail());
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
            }
            switch (profileRequest.getUpdateProfileType()) {
                case ADD_PHONE_NUMBER:
                    validateStateTransition(session.get(), ADDED_UNVERIFIED_PHONE_NUMBER);
                    authenticationService.updatePhoneNumber(
                            profileRequest.getEmail(), profileRequest.getProfileInformation());
                    sessionService.save(session.get().setState(ADDED_UNVERIFIED_PHONE_NUMBER));
                    LOGGER.info(
                            "Phone number updated and session state changed. Session state {}",
                            ADDED_UNVERIFIED_PHONE_NUMBER);
                    return generateApiGatewayProxyResponse(
                            200, new BaseAPIResponse(session.get().getState()));
                case CAPTURE_CONSENT:
                    Optional<ClientSession> clientSession =
                            clientSessionService.getClientSessionFromRequestHeaders(
                                    input.getHeaders());

                    if (!clientSession.isPresent()) {
                        LOGGER.info("ClientSession not found.");
                        return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1020);
                    }

                    try {
                        AuthorizationRequest authorizationRequest =
                                AuthorizationRequest.parse(
                                        clientSession.get().getAuthRequestParams());
                        clientId = authorizationRequest.getClientID().getValue();
                    } catch (ParseException e) {
                        LOGGER.info("Cannot retreive auth request params from client session id.");
                        return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
                    }

                    Optional<Map<String, List<String>>> clientConsents =
                            authenticationService.getUserConsents(profileRequest.getEmail());

                    if (clientConsents.isPresent() && clientConsents.get().containsKey(clientId)) {
                        clientConsents.get().get(clientId).clear();
                        clientConsents
                                .get()
                                .get(clientId)
                                .add(profileRequest.getProfileInformation());
                        LOGGER.info(
                                "Consent value successfully added to clientConsent map. Client ID {} - Consent Value {}",
                                clientId,
                                profileRequest.getProfileInformation());
                    } else {
                        clientConsents =
                                Optional.of(
                                        Map.of(
                                                clientId,
                                                List.of(profileRequest.getProfileInformation())));
                        LOGGER.info(
                                "New consent map created. Client ID {} - Consent Value {}",
                                clientId,
                                profileRequest.getProfileInformation());
                    }

                    authenticationService.updateConsent(
                            profileRequest.getEmail(), clientConsents.get());
                    sessionService.save(session.get().setState(ADDED_CONSENT));

                    LOGGER.info(
                            "Consent updated and session state changed. Session state {}",
                            ADDED_CONSENT);
                    try {
                        return generateApiGatewayProxyResponse(
                                200, new BaseAPIResponse(session.get().getState()));
                    } catch (JsonProcessingException e) {
                        LOGGER.info("JsonProcessingException : {}", e);
                    }
            }
        } catch (JsonProcessingException e) {
            LOGGER.info("JsonProcessingException : {}", e);
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        } catch (InvalidStateTransitionException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1019);
        }

        return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1013);
    }
}
