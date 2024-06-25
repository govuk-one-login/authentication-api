package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.nimbusds.jose.KeySourceException;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.entity.JwksResponse;
import uk.gov.di.orchestration.shared.services.JwksService;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class FetchJwksHandlerTest {

    private static final Context CONTEXT = mock(Context.class);
    JwksService jwksService = mock(JwksService.class);
    private final FetchJwksHandler handler = new FetchJwksHandler(jwksService);
    private final String keyId = "some-key-id";
    private final String url = "https://oidc.test.account.gov.uk/.well-known/jwk.json";

    @Test
    void returnsErrorWhenServiceThrowsKeySourceException()
            throws MalformedURLException, KeySourceException {
        // given
        Map<String, String> event = Map.of("url", url, "keyId", keyId);
        when(jwksService.retrieveJwkFromURLWithKeyId(new URL(url), keyId))
                .thenThrow(new KeySourceException());

        // when
        JwksResponse response = handler.handleRequest(event, CONTEXT);

        // then
        assertThat(response.error().getCode(), equalTo("server_error"));
        assertThat(response.jwk(), equalTo(null));
    }

    @Test
    void returnsErrorWhenUrlIsMissing() {
        // given
        Map<String, String> event = Map.of("keyId", keyId);

        // when
        JwksResponse response = handler.handleRequest(event, CONTEXT);

        // then
        assertThat(response.error().getCode(), equalTo("server_error"));
        assertThat(response.jwk(), equalTo(null));
    }

    @Test
    void returnsErrorWhenKeyIdIsMissing() {
        // given
        Map<String, String> event = Map.of("url", url);

        // when
        JwksResponse response = handler.handleRequest(event, CONTEXT);

        // then
        assertThat(response.error().getCode(), equalTo("server_error"));
        assertThat(response.jwk(), equalTo(null));
    }
}
