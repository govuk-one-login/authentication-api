package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.services.JwksService;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
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
    void returnsAJwkWhenUrlAndKeyIdAreValid()
            throws MalformedURLException, KeySourceException, ParseException {
        // given
        Map<String, String> event = Map.of("url", url, "keyId", keyId);
        String jwkJson =
                "{\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"P-256\",\"kid\":\"f27ff20940cdc6c8b34f97f44c24c8601ded9465c0713dd190ed152272d07ddb\",\"x\":\"sSdmBkED2EfjTdX-K2_cT6CfBwXQFt-DJ6v8-6tr_n8\",\"y\":\"WTXmQdqLwrmHN5tiFsTFUtNAvDYhhTQB4zyfteCrWIE\",\"alg\":\"ES256\"}";
        JWK jwk = JWK.parse(jwkJson);
        when(jwksService.retrieveJwkFromURLWithKeyId(new URL(url), keyId)).thenReturn(jwk);

        // when
        String response = handler.handleRequest(event, CONTEXT);

        // then
        assertThat(response, equalTo(jwkJson));
    }

    @Test
    void returnsErrorWhenServiceThrowsKeySourceException()
            throws MalformedURLException, KeySourceException {
        // given
        Map<String, String> event = Map.of("url", url, "keyId", keyId);
        when(jwksService.retrieveJwkFromURLWithKeyId(new URL(url), keyId))
                .thenThrow(new KeySourceException());

        // when
        String response = handler.handleRequest(event, CONTEXT);

        // then
        assertThat(response, equalTo("error"));
    }

    @Test
    void returnsErrorWhenUrlIsMissing() {
        // given
        Map<String, String> event = Map.of("keyId", keyId);

        // when
        String response = handler.handleRequest(event, CONTEXT);

        // then
        assertThat(response, equalTo("error"));
    }

    @Test
    void returnsErrorWhenKeyIdIsMissing() {
        // given
        Map<String, String> event = Map.of("url", url);

        // when
        String response = handler.handleRequest(event, CONTEXT);

        // then
        assertThat(response, equalTo("error"));
    }

    @Test
    void returnsErrorWhenUrlIsMalformed() {
        // given
        Map<String, String> event = Map.of("url", "not-a-valid-url", "keyId", keyId);

        // when
        String response = handler.handleRequest(event, CONTEXT);

        // then
        assertThat(response, equalTo("error"));
    }
}
