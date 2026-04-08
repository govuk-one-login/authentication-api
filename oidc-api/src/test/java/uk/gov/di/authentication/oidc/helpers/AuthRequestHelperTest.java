package uk.gov.di.authentication.oidc.helpers;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.oidc.helpers.AuthRequestHelper.getCustomParameterOpt;

public class AuthRequestHelperTest {
    @Test
    void shouldReturnEmptyOptionalWhenCustomParameterIsNull() {
        var authRequest = authRequestBuilder().build();

        assertThat(
                getCustomParameterOpt(authRequest, "not-a-parameter"), equalTo(Optional.empty()));
    }

    @Test
    void shouldReturnOptionalWhenCustomParameterIsNotNull() {
        var authRequest = authRequestBuilder().customParameter("test-parameter", "abc").build();

        assertThat(
                getCustomParameterOpt(authRequest, "test-parameter"), equalTo(Optional.of("abc")));
    }

    private AuthenticationRequest.Builder authRequestBuilder() {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        return new AuthenticationRequest.Builder(
                        ResponseType.CODE,
                        scope,
                        new ClientID("test-id"),
                        URI.create("https://localhost:8080"))
                .state(new State())
                .nonce(new Nonce());
    }
}
