package uk.gov.di.authentication.ipv.services;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.State;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class IPVAuthorisationResponseServiceTest {

    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private static final State STATE = new State();
    private final AuthorisationResponseService authorisationResponseService =
            new AuthorisationResponseService();

    @Test
    void shouldReturnOptionalEmptyWhenNoErrorIsPresent() {
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());

        assertThat(
                authorisationResponseService.validateResponse(responseHeaders),
                equalTo(Optional.empty()));
    }

    @Test
    void shouldReturnErrorObjectWhenResponseContainsError() {
        ErrorObject errorObject =
                new ErrorObject(
                        "invalid_request_redirect_uri", "redirect_uri param must be provided");
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());
        responseHeaders.put("error", errorObject.toString());

        assertThat(
                authorisationResponseService.validateResponse(responseHeaders),
                equalTo(Optional.of(new ErrorObject(errorObject.getCode()))));
    }

    @Test
    void shouldReturnErrorObjectWhenResponseContainsNoQueryParams() {
        assertThat(
                authorisationResponseService.validateResponse(Collections.emptyMap()),
                equalTo(
                        Optional.of(
                                new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "No query parameters present"))));
    }

    @Test
    void shouldReturnErrorObjectWhenResponseContainsNoStateParam() {
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());

        assertThat(
                authorisationResponseService.validateResponse(responseHeaders),
                equalTo(
                        Optional.of(
                                new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "No state param present in Authorisation response"))));
    }

    @Test
    void shouldReturnErrorObjectWhenResponseContainsNoCodeParam() {
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("state", STATE.getValue());

        assertThat(
                authorisationResponseService.validateResponse(responseHeaders),
                equalTo(
                        Optional.of(
                                new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "No code param present in Authorisation response"))));
    }
}
