package uk.gov.di.authentication.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.entity.IdentityResponse;
import uk.gov.di.authentication.oidc.lambda.IdentityHandler;
import uk.gov.di.authentication.shared.entity.AccessTokenStore;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.helper.KeyPairHelper;

import java.security.KeyPair;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class IdentityIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String CLIENT_ID = "client-id-one";
    private static final String ACCESS_TOKEN_PREFIX = "ACCESS_TOKEN:";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";

    @BeforeEach
    void setup() {
        handler = new IdentityHandler(TEST_CONFIGURATION_SERVICE);
    }

    @Test
    void shouldReturn204WhenCallingIdentityLambda() throws JsonProcessingException {
        Subject internalSubject = new Subject();
        Subject publicSubject = new Subject();
        LocalDateTime localDateTime = LocalDateTime.now().plusMinutes(10);
        Date expiryDate = Date.from(localDateTime.atZone(ZoneId.of("UTC")).toInstant());
        List<String> scopes = new ArrayList<>();
        scopes.add("email");
        scopes.add("phone");
        scopes.add("openid");
        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .claim("scope", scopes)
                        .issuer("issuer-id")
                        .expirationTime(expiryDate)
                        .issueTime(
                                Date.from(LocalDateTime.now().atZone(ZoneId.of("UTC")).toInstant()))
                        .claim("client_id", "client-id-one")
                        .subject(publicSubject.getValue())
                        .jwtID(UUID.randomUUID().toString())
                        .build();
        SignedJWT signedJWT = tokenSigner.signJwt(claimsSet);
        AccessToken accessToken = new BearerAccessToken(signedJWT.serialize());
        AccessTokenStore accessTokenStore =
                new AccessTokenStore(accessToken.getValue(), internalSubject.getValue());
        String accessTokenStoreString = new ObjectMapper().writeValueAsString(accessTokenStore);
        redis.addToRedis(
                ACCESS_TOKEN_PREFIX + CLIENT_ID + "." + publicSubject,
                accessTokenStoreString,
                300L);
        SignedJWT signedCredential = generateSignedCredential();
        setUpDynamo(publicSubject.getValue(), signedCredential.serialize());

        var response =
                makeRequest(
                        Optional.empty(),
                        Map.of("Authorization", accessToken.toAuthorizationHeader()),
                        Map.of());

        assertThat(response, hasStatus(200));

        IdentityResponse identityResponse =
                new ObjectMapper().readValue(response.getBody(), IdentityResponse.class);
        assertThat(identityResponse.getSub(), equalTo(publicSubject.getValue()));
        assertThat(identityResponse.getIdentityCredential(), equalTo(signedCredential.serialize()));
    }

    private void setUpDynamo(String subject, String serializedCredential) {
        KeyPair keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
        spotStore.addCredential(subject, serializedCredential);
        clientStore.registerClient(
                CLIENT_ID,
                "test-client",
                singletonList("redirect-url"),
                singletonList(TEST_EMAIL_ADDRESS),
                List.of("openid", "email", "phone"),
                Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                singletonList("http://localhost/post-redirect-logout"),
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public",
                true);
    }

    public SignedJWT generateSignedCredential() {
        try {
            ECKey ecSigningKey =
                    new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
            JWSSigner signer = new ECDSASigner(ecSigningKey);
            JWSHeader jwsHeader =
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .keyID(ecSigningKey.getKeyID())
                            .build();
            var signedJWT = new SignedJWT(jwsHeader, new JWTClaimsSet.Builder().build());
            signedJWT.sign(signer);
            return signedJWT;
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }
}
