package uk.gov.di.authentication.sharedtest.extensions;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import uk.gov.di.authentication.sharedtest.httpstub.HttpStubExtension;

import static java.lang.String.format;

public class CriStubExtension extends HttpStubExtension {

    private final ECKey signingKey;
    private final String credential =
            "{"
                    + "  \"sub\": \"urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6\","
                    + "  \"nbf\": 1647017990,"
                    + "  \"iss\": \"http://cri\","
                    + "  \"iat\": 1647017990,"
                    + "  \"vc\": {"
                    + "    \"@context\": ["
                    + "      \"https://www.w3.org/2018/credentials/v1\","
                    + "      \"https://vocab.london.cloudapps.digital/contexts/identity-v1.jsonld\""
                    + "    ],"
                    + "    \"type\": ["
                    + "      \"VerifiableCredential\","
                    + "      \"AddressCredential\""
                    + "    ],"
                    + "    \"credentialSubject\": {"
                    + "    }"
                    + "  }"
                    + "}";

    public CriStubExtension(int port, ECKey signingKey) {
        super(port);
        this.signingKey = signingKey;
    }

    public CriStubExtension(ECKey signingKey) {
        super();
        this.signingKey = signingKey;
    }

    public void init() throws JOSEException {
        register(
                "/token",
                200,
                "application/json",
                format(
                        "{"
                                + "  \"access_token\": \"740e5834-3a29-46b4-9a6f-16142fde533a\","
                                + "  \"token_type\": \"bearer\","
                                + "  \"expires_in\": \"3600\","
                                + "  \"uri\": \"http://localhost:%1$d\""
                                + "}",
                        getHttpPort()));

        register("/protected-resource", 200, "application/jwt", signedResponse());
    }

    private String signedResponse() throws JOSEException {
        JWSSigner signer = new ECDSASigner(signingKey);
        JWSObject jwsObject =
                new JWSObject(
                        new JWSHeader.Builder(JWSAlgorithm.ES256)
                                .keyID(signingKey.getKeyID())
                                .build(),
                        new Payload(credential));
        jwsObject.sign(signer);
        return jwsObject.serialize();
    }
}
