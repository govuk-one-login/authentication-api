package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import uk.gov.di.entity.AuthCodeRequest;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.entity.Session;
import uk.gov.di.exceptions.ClientNotFoundException;
import uk.gov.di.services.AuthorizationService;
import uk.gov.di.services.CodeStorageService;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.RedisConnectionService;
import uk.gov.di.services.SessionService;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.entity.SessionState.AUTHENTICATED;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;

public class AuthCodeHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final SessionService sessionService;
    private final CodeStorageService codeStorageService;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final ConfigurationService configurationService;
    private final AuthorizationService authorizationService;

    public AuthCodeHandler(
            SessionService sessionService,
            CodeStorageService codeStorageService,
            ConfigurationService configurationService,
            AuthorizationService authorizationService) {
        this.sessionService = sessionService;
        this.codeStorageService = codeStorageService;
        this.configurationService = configurationService;
        this.authorizationService = authorizationService;
    }

    public AuthCodeHandler() {
        configurationService = new ConfigurationService();
        sessionService = new SessionService(configurationService);
        codeStorageService =
                new CodeStorageService(new RedisConnectionService(configurationService));
        authorizationService = new AuthorizationService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        Optional<Session> session = sessionService.getSessionFromRequestHeaders(input.getHeaders());
        if (session.isEmpty()) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
        }
        AuthorizationRequest authorizationRequest;
        AuthCodeRequest authCodeRequest;
        try {
            authCodeRequest = objectMapper.readValue(input.getBody(), AuthCodeRequest.class);
            Map<String, List<String>> authRequest =
                    session.get()
                            .getClientSessions()
                            .get(authCodeRequest.getClientSessionId())
                            .getAuthRequestParams();
            authorizationRequest = AuthorizationRequest.parse(authRequest);
            if (!authorizationService.isClientRedirectUriValid(
                    authorizationRequest.getClientID(), authorizationRequest.getRedirectionURI())) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1017);
            }
        } catch (ParseException | JsonProcessingException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        } catch (ClientNotFoundException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1016);
        }

        AuthorizationCode authCode = new AuthorizationCode();
        codeStorageService.saveAuthorizationCode(
                new AuthorizationCode().getValue(),
                authCodeRequest.getClientSessionId(),
                configurationService.getAuthCodeExpiry());
        AuthenticationSuccessResponse authenticationResponse =
                authorizationService.generateSuccessfulAuthResponse(authorizationRequest, authCode);
        sessionService.save(session.get().setState(AUTHENTICATED));
        return new APIGatewayProxyResponseEvent()
                .withStatusCode(302)
                .withHeaders(Map.of("Location", authenticationResponse.toURI().toString()));
    }
}
