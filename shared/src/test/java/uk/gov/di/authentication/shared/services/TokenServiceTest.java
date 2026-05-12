package uk.gov.di.authentication.shared.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.approvaltests.JsonApprovals;
import org.approvaltests.core.Options;
import org.approvaltests.scrubbers.GuidScrubber;
import org.approvaltests.scrubbers.RegExScrubber;
import org.approvaltests.scrubbers.Scrubbers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.authentication.sharedtest.helper.SubjectHelper;
import uk.gov.di.authentication.sharedtest.helper.TokenGeneratorHelper;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.text.ParseException;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class TokenServiceTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);
    private final TokenService tokenService =
            new TokenService(configurationService, kmsConnectionService);
    private static final Subject PUBLIC_SUBJECT = SubjectHelper.govUkSignInSubject();
    private static final Subject FIXED_INTERNAL_PAIRWISE_SUBJECT =
            new Subject("urn:fdc:gov.uk:2022:TJLt3WaiGkLh8UqeisH2zVKGAP0");
    private static final Scope SCOPES =
            new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.PHONE);
    private static final String CLIENT_ID = "client-id";
    private static final String BASE_URL = "https://example.com";
    private static final String KEY_ID = "14342354354353";
    private static final String STORAGE_TOKEN_PREFIX =
            "eyJraWQiOiIxZDUwNGFlY2UyOThhMTRkNzRlZTBhMDJiNjc0MGI0MzcyYTFmYWI0MjA2Nzc4ZTQ4NmJhNzI3NzBmZjRiZWI4IiwiYWxnIjoiRVMyNTYifQ.";
    private static final String IPV_AUDIENCE = "https://identity.test.account.gov.uk";
    private static final String EVCS_AUDIENCE = "https://credential-store.test.account.gov.uk";

    @RegisterExtension
    public final CaptureLoggingExtension logging = new CaptureLoggingExtension(TokenService.class);

    @BeforeEach
    void setUp() {
        when(configurationService.getOidcApiBaseURL()).thenReturn(Optional.of(BASE_URL));
        when(configurationService.getAccessTokenExpiry()).thenReturn(300L);
        when(configurationService.getIDTokenExpiry()).thenReturn(120L);
        when(configurationService.getSessionExpiry()).thenReturn(300L);
        when(configurationService.getEnvironment()).thenReturn("test");
        when(kmsConnectionService.getPublicKey(any(GetPublicKeyRequest.class)))
                .thenReturn(GetPublicKeyResponse.builder().keyId("789789789789789").build());
    }

    @AfterEach
    void tearDown() {
        assertThat(logging.events(), not(hasItem(withMessageContaining(CLIENT_ID))));
    }

    @Test
    void shouldGenerateWellFormedStorageTokenForMfaReset() throws JOSEException, ParseException {
        when(configurationService.getEVCSAudience()).thenReturn(EVCS_AUDIENCE);
        when(configurationService.getIPVAudience()).thenReturn(IPV_AUDIENCE);
        createSignedToken();

        AccessToken token =
                tokenService.generateStorageTokenForMfaReset(FIXED_INTERNAL_PAIRWISE_SUBJECT);
        var parsedToken = SignedJWT.parse(token.getValue());

        verify(configurationService).getMfaResetStorageTokenSigningKeyAlias();
        assertEquals(3, parsedToken.getParsedParts().length);
        assertThat(token.toString(), startsWith(STORAGE_TOKEN_PREFIX));
        var unixTimestampScrubber = new RegExScrubber("\\d{10}", "1700000000");
        var guidScrubber = new GuidScrubber();
        JsonApprovals.verifyAsJson(
                parsedToken.getJWTClaimsSet().toJSONObject(),
                new Options(Scrubbers.scrubAll(unixTimestampScrubber, guidScrubber)));
    }

    private void createSignedToken() throws JOSEException {
        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256)
                        .keyID(KEY_ID)
                        .algorithm(JWSAlgorithm.ES256)
                        .generate();
        ECDSASigner signer = new ECDSASigner(ecSigningKey);
        SignedJWT signedJWT =
                TokenGeneratorHelper.generateSignedToken(
                        CLIENT_ID,
                        BASE_URL,
                        SCOPES.toStringList(),
                        signer,
                        PUBLIC_SUBJECT,
                        ecSigningKey.getKeyID());
        byte[] tokenSignatureDer = ECDSA.transcodeSignatureToDER(signedJWT.getSignature().decode());
        SignResponse tokenResult =
                SignResponse.builder()
                        .signature(SdkBytes.fromByteArray(tokenSignatureDer))
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .keyId(KEY_ID)
                        .build();

        when(kmsConnectionService.sign(any(SignRequest.class))).thenReturn(tokenResult);
    }
}
