package uk.gov.di.authentication.shared.helpers;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.sharedtest.helper.KeyPairHelper;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.Objects;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DocAppSubjectIdHelperTest {

    private static final String REDIRECT_URI = "https://localhost:8080";
    private static final Scope SCOPE =
            new Scope(OIDCScopeValue.OPENID, CustomScopeValue.DOC_CHECKING_APP);
    private static final State STATE = new State();
    private static final Nonce NONCE = new Nonce();
    private static final ClientID CLIENT_ID = new ClientID("test-id");
    private static final URI DOC_APP_DOMAIN = URI.create("https://doc-app-domain.gov.uk");
    private static final String AUDIENCE = "https://localhost/authorize";

    @Test
    void shouldUseSubjectFromRequestObjectWhenPresentAndCustomDocAppClaimEnabled()
            throws JOSEException {
        var expectedSubject = new Subject();
        var clientSession = generateClientSession(expectedSubject);

        var docAppSubjectId =
                DocAppSubjectIdHelper.calculateDocAppSubjectId(clientSession, true, DOC_APP_DOMAIN);

        assertThat(docAppSubjectId, equalTo(expectedSubject));
    }

    @Test
    void
            shouldUsePairwiseSubjectWhenSubjectInRequestObjectIsPresentButCustomDocAppClaimIsNotEnabled()
                    throws JOSEException {
        var expectedSubject = new Subject();
        var clientSession = generateClientSession(expectedSubject);

        var docAppSubjectId =
                DocAppSubjectIdHelper.calculateDocAppSubjectId(
                        clientSession, false, DOC_APP_DOMAIN);

        assertThat(docAppSubjectId, not(equalTo(expectedSubject)));
        assertTrue(docAppSubjectId.getValue().startsWith("urn:fdc:gov.uk:2022:"));
    }

    @Test
    void shouldUsePairwiseSubjectWhenSubjectNotPresentInRequestObjectAndCustomAppClaimIsNotEnabled()
            throws JOSEException {
        var clientSession = generateClientSession(null);

        var docAppSubjectId =
                DocAppSubjectIdHelper.calculateDocAppSubjectId(
                        clientSession, false, DOC_APP_DOMAIN);

        assertTrue(docAppSubjectId.getValue().startsWith("urn:fdc:gov.uk:2022:"));
    }

    @Test
    void shouldUsePairwiseSubjectWhenCustomAppClaimIsEnabledButSubjectNotPresentInRequestObject()
            throws JOSEException {
        var clientSession = generateClientSession(null);

        var docAppSubjectId =
                DocAppSubjectIdHelper.calculateDocAppSubjectId(clientSession, true, DOC_APP_DOMAIN);

        assertTrue(docAppSubjectId.getValue().startsWith("urn:fdc:gov.uk:2022:"));
    }

    private ClientSession generateClientSession(Subject subject) throws JOSEException {
        var jwtClaimsSetBuilder =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE.toString())
                        .claim("nonce", NONCE)
                        .claim("state", STATE)
                        .claim("client_id", CLIENT_ID)
                        .issuer(new ClientID("test-id").getValue());
        if (Objects.nonNull(subject)) {
            jwtClaimsSetBuilder.subject(subject.getValue());
        }
        var jwsHeader = new JWSHeader(JWSAlgorithm.RS256);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSetBuilder.build());
        var signer = new RSASSASigner(KeyPairHelper.GENERATE_RSA_KEY_PAIR().getPrivate());
        signedJWT.sign(signer);
        var authRequest =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE, SCOPE, CLIENT_ID, URI.create(REDIRECT_URI))
                        .state(STATE)
                        .nonce(new Nonce())
                        .requestObject(signedJWT)
                        .build();
        return new ClientSession(
                authRequest.toParameters(),
                LocalDateTime.now(),
                VectorOfTrust.getDefaults(),
                "client-name");
    }
}
