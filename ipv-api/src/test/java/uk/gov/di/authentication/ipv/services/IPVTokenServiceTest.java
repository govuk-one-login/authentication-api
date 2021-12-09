package uk.gov.di.authentication.ipv.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;

import java.net.URI;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.ipv.services.IPVTokenService.IPV_ACCESS_TOKEN_PREFIX;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;

class IPVTokenServiceTest {

    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private static final URI IPV_URI = URI.create("http://ipv");
    private static final ClientID CLIENT_ID = new ClientID("some-client-id");
    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private IPVTokenService ipvTokenService;

    @BeforeEach
    void setUp() {
        ipvTokenService = new IPVTokenService(configService, redisConnectionService);
        when(configService.getIPVAuthorisationURI()).thenReturn(IPV_URI);
        when(configService.getIPVAuthorisationClientId()).thenReturn(CLIENT_ID.getValue());
        when(configService.getAccessTokenExpiry()).thenReturn(300L);
    }

    @Test
    void shouldConstructTokenRequest() {
        TokenRequest tokenRequest = ipvTokenService.constructTokenRequest(AUTH_CODE.getValue());

        assertThat(
                tokenRequest.getCustomParameters().get("client_id").get(0),
                equalTo(CLIENT_ID.getValue()));
        assertThat(tokenRequest.getEndpointURI(), equalTo(buildURI(IPV_URI.toString(), "token")));
        assertThat(
                tokenRequest.getClientAuthentication().getMethod().getValue(),
                equalTo("private_key_jwt"));
    }

    @Test
    void shouldCallRedisWhenSavingAccessToken() throws JsonProcessingException {
        AccessToken accessToken = new BearerAccessToken();
        String sessionID = "session-id";
        ipvTokenService.saveAccessTokenToRedis(accessToken, sessionID);

        verify(redisConnectionService)
                .saveWithExpiry(
                        IPV_ACCESS_TOKEN_PREFIX + sessionID,
                        new ObjectMapper().writeValueAsString(accessToken),
                        300L);
    }
}
