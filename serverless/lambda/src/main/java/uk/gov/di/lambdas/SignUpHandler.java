package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.UserService;
import uk.gov.di.services.ValidationService;
import uk.gov.di.validation.PasswordValidation;

import java.util.Map;
import java.util.Set;

import static uk.gov.di.helpers.RequestBodyHelper.PARSE_REQUEST_BODY;

public class SignUpHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private AuthenticationService authenticationService;
    private ValidationService validationService;

    public SignUpHandler(AuthenticationService authenticationService, ValidationService validationService) {
        this.authenticationService = authenticationService;
        this.validationService = validationService;
    }

    public SignUpHandler() {
        this.authenticationService = new UserService();
        this.validationService = new ValidationService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        APIGatewayProxyResponseEvent apiGatewayProxyResponseEvent = new APIGatewayProxyResponseEvent();
        LambdaLogger logger = context.getLogger();

        Map<String, String> requestBody = PARSE_REQUEST_BODY(input.getBody());

        if (!requestBody.containsKey("email") || !requestBody.containsKey("password") || !requestBody.containsKey("password-confirm")) {
            apiGatewayProxyResponseEvent.setStatusCode(400);
            apiGatewayProxyResponseEvent.setBody("Request is missing parameters");
            return apiGatewayProxyResponseEvent;
        }

        String password = requestBody.get("password");
        String passwordConfirm = requestBody.get("password-confirm");
        String email = requestBody.get("email");
        Set<PasswordValidation> passwordValidationErrors = validationService.validatePassword(password, passwordConfirm);

        if (passwordValidationErrors.isEmpty()) {
            authenticationService.signUp(email, password);
            apiGatewayProxyResponseEvent.setStatusCode(200);
            return apiGatewayProxyResponseEvent;
        } else {
            apiGatewayProxyResponseEvent.setStatusCode(400);
            apiGatewayProxyResponseEvent.setBody(passwordValidationErrors.toString());
            return apiGatewayProxyResponseEvent;
        }
    }
}
