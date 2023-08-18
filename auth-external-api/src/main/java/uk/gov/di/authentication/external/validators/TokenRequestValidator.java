package uk.gov.di.authentication.external.validators;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;

import java.util.Map;
import java.util.Optional;

public class TokenRequestValidator {
    private final String redirectUri;
    private final String clientId;

    TokenRequestValidator(String redirectUri, String clientId) {
        this.redirectUri = redirectUri;
        this.clientId = clientId;
    }

    public Optional<ErrorObject> validate(Map<Object, Object> requestParameters) {
        if (!requestParameters.containsKey("grant_type")) {
            return invalidRequestCode("Request is missing grant_type parameter");
        }

        if (!"authorization_code".equals(requestParameters.get("grant_type"))) {
            return invalidRequestCode("Request has invalid grant_type parameter");
        }

        if (!requestParameters.containsKey("code") || requestParameters.get("code") == null) {
            return invalidRequestCode("Request is missing code parameter");
        }

        if (!requestParameters.containsKey("redirect_uri")) {
            return invalidRequestCode("Request is missing redirect_uri parameter");
        }

        if (!redirectUri.equals(requestParameters.get("redirect_uri"))) {
            return invalidRequestCode("Request redirect_uri is not the permitted redirect_uri");
        }

        if (!requestParameters.containsKey("client_id")) {
            return invalidRequestCode("Request is missing client_id parameter");
        }

        if (!clientId.equals(requestParameters.get("client_id"))) {
            return invalidRequestCode("Request client_id is not the permitted client_id");
        }

        return Optional.empty();
    }

    private static Optional<ErrorObject> invalidRequestCode(String description) {
        return Optional.of(new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, description));
    }
}
