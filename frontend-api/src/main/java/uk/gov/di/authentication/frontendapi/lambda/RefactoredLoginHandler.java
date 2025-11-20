package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import uk.gov.di.authentication.frontendapi.entity.LoginRequest;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.userpermissions.entity.Decision;
import uk.gov.di.authentication.userpermissions.entity.UserPermissionContext;

import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;

/**
 * Refactored LoginHandler demonstrating method chaining with the existing Result pattern.
 * This shows how the complex nested logic can be simplified using functional composition.
 * 
 * TESTING APPROACH:
 * Use TDD with public methods first, then extract private methods during refactoring.
 * Test all scenarios through handleRequestWithUserContext by mocking dependencies
 * and crafting specific inputs to exercise each validation path.
 * 
 * BENEFITS OF THIS REFACTOR:
 * 
 * Code Structure & Readability:
 * - Eliminates deep nesting: Original had 4+ levels of if/else, now linear chain
 * - Clear flow: validateUserExists -> createContext -> checkPermission -> handleDecision
 * - Single responsibility: Each method does one thing and returns a Result
 * - Reduced complexity: Main method is 8 lines vs original's 200+ lines
 * 
 * Error Handling:
 * - Consistent error propagation: All errors flow through Result type automatically
 * - No scattered return statements: Error handling centralized in fold() call
 * - Type-safe errors: LoginError encapsulates status code and ErrorResponse
 * - Early termination: Failed steps automatically short-circuit the chain
 * 
 * Maintainability:
 * - Composable functions: Easy to add/remove/reorder validation steps
 * - Immutable data flow: No shared mutable state between steps
 * - Clear contracts: Each method's input/output types are explicit
 * - Easier debugging: Can inspect Result at each step in the chain
 * 
 * Testing Benefits:
 * - Black-box testing: Test behavior through public interface, not implementation details
 * - Mockable dependencies: Pure functions easier to mock/stub at service layer
 * - Predictable outcomes: Given inputs always produce same Result
 * - Edge case testing: Craft inputs to trigger specific validation failures (e.g., missing user)
 * - Behavioral verification: Test what the handler does, not how it does it
 * - Refactoring safety: Private method changes don't break tests
 * - Reduced test complexity: Single entry point with clear input/output contract
 * - TDD-friendly: Start with public methods, extract private methods during refactoring
 * - Better encapsulation: Private methods remain implementation details
 */
public class RefactoredLoginHandler extends BaseFrontendHandler<LoginRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    // Dependencies would be injected here - simplified for example
    
    public RefactoredLoginHandler() {
        super(LoginRequest.class, ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            LoginRequest request,
            UserContext userContext) {

        return fold(
            validateUserExists(request, userContext)
                .flatMap(profile -> createUserPermissionContext(profile, userContext))
                .flatMap(ctx -> checkPasswordPermission(ctx, request.getJourneyType()))
                .flatMap(decision -> handlePermissionDecision(decision, request, userContext)),
            error -> generateApiGatewayProxyErrorResponse(error.statusCode(), error.errorResponse()),
            response -> response
        );
    }

    // Helper method to simulate fold functionality
    private <F, S, R> R fold(Result<F, S> result, 
                             java.util.function.Function<F, R> onFailure, 
                             java.util.function.Function<S, R> onSuccess) {
        return result.isSuccess() ? onSuccess.apply(result.getSuccess()) : onFailure.apply(result.getFailure());
    }

    private Result<LoginError, UserProfile> validateUserExists(LoginRequest request, UserContext userContext) {
        return authenticationService.getUserProfileByEmailMaybe(request.getEmail())
                .filter(profile -> userContext.getUserCredentials().isPresent())
                .map(Result::<LoginError, UserProfile>success)
                .orElse(Result.failure(new LoginError(400, ErrorResponse.ACCT_DOES_NOT_EXIST)));
    }

    private Result<LoginError, UserPermissionContext> createUserPermissionContext(
            UserProfile userProfile, UserContext userContext) {
        try {
            var calculatedPairwiseId = calculatePairwiseId(userContext, userProfile);
            var context = new UserPermissionContext(
                    userProfile.getSubjectID(),
                    calculatedPairwiseId,
                    userProfile.getEmail(),
                    null);
            return Result.success(context);
        } catch (Exception e) {
            return Result.failure(new LoginError(500, ErrorResponse.REQUEST_MISSING_PARAMS));
        }
    }

    private Result<LoginError, Decision> checkPasswordPermission(
            UserPermissionContext context, JourneyType journeyType) {
        return permissionDecisionManager.canReceivePassword(journeyType, context)
                .mapFailure(decisionError -> new LoginError(500, ErrorResponse.REQUEST_MISSING_PARAMS));
    }

    private Result<LoginError, APIGatewayProxyResponseEvent> handlePermissionDecision(
            Decision decision, LoginRequest request, UserContext userContext) {
        
        if (decision instanceof Decision.TemporarilyLockedOut lockedOut) {
            return handleTemporaryLockout(lockedOut, request, userContext);
        }
        
        if (!(decision instanceof Decision.Permitted)) {
            return Result.failure(new LoginError(500, ErrorResponse.UNHANDLED_NEGATIVE_DECISION));
        }

        return validateCredentials(request, userContext)
                .flatMap(valid -> valid 
                    ? handleValidCredentials(request, userContext)
                    : handleInvalidCredentials(request, userContext));
    }

    private Result<LoginError, APIGatewayProxyResponseEvent> handleTemporaryLockout(
            Decision.TemporarilyLockedOut lockedOut, LoginRequest request, UserContext userContext) {
        
        var journeyType = Optional.ofNullable(request.getJourneyType()).orElse(JourneyType.SIGN_IN);
        var isReauthJourney = journeyType == JourneyType.REAUTHENTICATION;
        
        if (isReauthJourney) {
            // Handle reauth lockout logic
            return Result.failure(new LoginError(400, ErrorResponse.TOO_MANY_INVALID_REAUTH_ATTEMPTS));
        } else {
            // Handle regular lockout logic  
            return Result.failure(new LoginError(400, ErrorResponse.TOO_MANY_INVALID_PW_ENTERED));
        }
    }

    private Result<LoginError, Boolean> validateCredentials(LoginRequest request, UserContext userContext) {
        try {
            var userProfile = userContext.getUserProfile().orElseThrow();
            boolean isValid = credentialsAreValid(request, userProfile);
            return Result.success(isValid);
        } catch (Exception e) {
            return Result.failure(new LoginError(500, ErrorResponse.REQUEST_MISSING_PARAMS));
        }
    }

    private Result<LoginError, APIGatewayProxyResponseEvent> handleValidCredentials(
            LoginRequest request, UserContext userContext) {
        // Implementation would call the existing handleValidCredentials method
        // This demonstrates how the complex logic can be broken down into composable parts
        return Result.success(generateSuccessResponse(request, userContext));
    }

    private Result<LoginError, APIGatewayProxyResponseEvent> handleInvalidCredentials(
            LoginRequest request, UserContext userContext) {
        // Implementation would call the existing handleInvalidCredentials method
        return Result.failure(new LoginError(401, ErrorResponse.INVALID_LOGIN_CREDS));
    }

    // Helper methods (simplified for example)
    private String calculatePairwiseId(UserContext userContext, UserProfile userProfile) {
        // Implementation from original handler
        return "calculated-pairwise-id";
    }

    private boolean credentialsAreValid(LoginRequest request, UserProfile userProfile) {
        // Implementation from original handler
        return true;
    }

    private APIGatewayProxyResponseEvent generateSuccessResponse(LoginRequest request, UserContext userContext) {
        // Implementation from original handler
        return new APIGatewayProxyResponseEvent();
    }

    // Error type for login operations
    public static class LoginError {
        private final int statusCode;
        private final ErrorResponse errorResponse;

        public LoginError(int statusCode, ErrorResponse errorResponse) {
            this.statusCode = statusCode;
            this.errorResponse = errorResponse;
        }

        public int statusCode() { return statusCode; }
        public ErrorResponse errorResponse() { return errorResponse; }
    }
}