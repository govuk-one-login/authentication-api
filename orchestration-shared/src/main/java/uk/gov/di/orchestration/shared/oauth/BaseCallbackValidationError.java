package uk.gov.di.orchestration.shared.oauth;

import com.nimbusds.oauth2.sdk.OAuth2Error;

public record BaseCallbackValidationError(String code, String description)
        implements CallbackValidationError {

    public static final BaseCallbackValidationError NO_QUERY_PARAMS =
            new BaseCallbackValidationError(
                    OAuth2Error.INVALID_REQUEST_CODE, "No query parameters present");

    public static final BaseCallbackValidationError NO_STATE =
            new BaseCallbackValidationError(
                    OAuth2Error.INVALID_REQUEST_CODE,
                    "No state param present in Authorisation response");

    public static final BaseCallbackValidationError INVALID_STATE =
            new BaseCallbackValidationError(
                    OAuth2Error.INVALID_REQUEST_CODE,
                    "Invalid state param present in Authorisation response");

    public static final BaseCallbackValidationError NO_CODE_IN_PARAMS =
            new BaseCallbackValidationError(
                    OAuth2Error.INVALID_REQUEST_CODE,
                    "No code param present in Authorisation response");
}
