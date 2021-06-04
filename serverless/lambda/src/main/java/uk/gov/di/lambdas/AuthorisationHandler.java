package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import uk.gov.di.services.AuthorizationCodeService;
import uk.gov.di.services.ClientService;
import uk.gov.di.services.InMemoryClientService;

import java.util.Map;
import java.util.Optional;

public class AuthorisationHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ClientService clientService;

    public AuthorisationHandler(ClientService clientService) {
        this.clientService = clientService;
    }

    public AuthorisationHandler() {
        this.clientService = new InMemoryClientService(new AuthorizationCodeService());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {

        try {
            var authRequest = AuthenticationRequest.parse(input.getMultiValueQueryStringParameters());

            Optional<ErrorObject> error = clientService.getErrorForAuthorizationRequest(authRequest);

            return error
                    .map(e -> errorResponse(authRequest, e))
                    .orElse(redirectResponse(authRequest));
        } catch (ParseException e) {
            APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
            response.setStatusCode(400);
            response.setBody("Cannot parse authentication request");

            return response;
        }
    }

    private APIGatewayProxyResponseEvent redirectResponse (AuthenticationRequest authRequest) {
        AuthenticationResponse authResponse = clientService
                .getSuccessfulResponse(authRequest, "joe.bloggs@digital.cabinet-office.gov.uk");
        return new APIGatewayProxyResponseEvent().withStatusCode(302).withHeaders(
                Map.of("Location", authResponse.toSuccessResponse().toURI().toString())
        );
    }

    private APIGatewayProxyResponseEvent errorResponse(AuthorizationRequest authRequest, ErrorObject errorObject) {
        AuthenticationErrorResponse error = new AuthenticationErrorResponse(
                authRequest.getRedirectionURI(),
                errorObject,
                authRequest.getState(),
                authRequest.getResponseMode());

        return new APIGatewayProxyResponseEvent().withStatusCode(302).withHeaders(
                Map.of("Location", error.toURI().toString())
        );
    }
}
