package uk.gov.di.authentication.external.validators;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TokenRequestValidatorTest {
    private static final String VALID_REDIRECT_URI = "https://redirect-uri.co.uk";
    private static final String VALID_CLIENT_ID = "client-id";
    private TokenRequestValidator validator =
            new TokenRequestValidator(VALID_REDIRECT_URI, VALID_CLIENT_ID);

    @Test
    void shouldReturnInvalidRequestCodeIfGivenNoGrantType() {
        Optional<ErrorObject> result = validator.validate(Map.of("key", "value"));

        assertEquals(OAuth2Error.INVALID_REQUEST_CODE, result.get().getCode());
        assertEquals("Request is missing grant_type parameter", result.get().getDescription());
    }

    @Test
    void shouldReturnInvalidRequestCodeIfGivenGrantTypeButOfInvalidValue() {
        Optional<ErrorObject> result = validator.validate(Map.of("grant_type", "value"));

        assertEquals(OAuth2Error.INVALID_REQUEST_CODE, result.get().getCode());
        assertEquals("Request has invalid grant_type parameter", result.get().getDescription());
    }

    @Test
    void shouldReturnInvalidRequestCodeIfGivenValidGrantTypeButNoCode() {
        Optional<ErrorObject> result =
                validator.validate(Map.of("grant_type", "authorization_code"));

        assertEquals(OAuth2Error.INVALID_REQUEST_CODE, result.get().getCode());
        assertEquals("Request is missing code parameter", result.get().getDescription());
    }

    @Test
    void shouldReturnInvalidRequestCodeIfGivenValidGrantTypeAndCodeButNoRedirectUri() {
        Optional<ErrorObject> result =
                validator.validate(Map.of("grant_type", "authorization_code", "code", "value"));

        assertEquals(OAuth2Error.INVALID_REQUEST_CODE, result.get().getCode());
        assertEquals("Request is missing redirect_uri parameter", result.get().getDescription());
    }

    @Test
    void
            shouldReturnInvalidRequestCodeIfGivenValidGrantTypeAndCodeAndRedirectUriOtherThanPermittedRedirectUri() {
        Optional<ErrorObject> result =
                validator.validate(
                        Map.of(
                                "grant_type",
                                "authorization_code",
                                "code",
                                "value",
                                "redirect_uri",
                                "value"));

        assertEquals(OAuth2Error.INVALID_REQUEST_CODE, result.get().getCode());
        assertEquals(
                "Request redirect_uri is not the permitted redirect_uri",
                result.get().getDescription());
    }

    @Test
    void
            shouldReturnInvalidRequestCodeIfGivenValidGrantTypeAndCodeAndPermittedRedirectButNoClientId() {
        Optional<ErrorObject> result =
                validator.validate(
                        Map.of(
                                "grant_type",
                                "authorization_code",
                                "code",
                                "value",
                                "redirect_uri",
                                VALID_REDIRECT_URI));

        assertEquals(OAuth2Error.INVALID_REQUEST_CODE, result.get().getCode());
        assertEquals("Request is missing client_id parameter", result.get().getDescription());
    }

    @Test
    void
            shouldReturnInvalidRequestCodeIfGivenValidGrantTypeAndCodeAndPermittedRedirectButInvalidClientId() {
        Optional<ErrorObject> result =
                validator.validate(
                        Map.of(
                                "grant_type",
                                "authorization_code",
                                "code",
                                "value",
                                "redirect_uri",
                                VALID_REDIRECT_URI,
                                "client_id",
                                "value"));

        assertEquals(OAuth2Error.INVALID_REQUEST_CODE, result.get().getCode());
        assertEquals(
                "Request client_id is not the permitted client_id", result.get().getDescription());
    }

    @Test
    void
            shouldReturnNoInvalidRequestCodeIfGivenValidGrantTypeAndCodeAndPermittedRedirectUriAndClientId() {
        Optional<ErrorObject> result =
                validator.validate(
                        Map.of(
                                "grant_type",
                                "authorization_code",
                                "code",
                                "value",
                                "redirect_uri",
                                VALID_REDIRECT_URI,
                                "client_id",
                                VALID_CLIENT_ID));

        assertEquals(Optional.empty(), result);
    }
}
