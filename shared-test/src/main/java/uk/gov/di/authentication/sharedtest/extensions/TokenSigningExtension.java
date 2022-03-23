package uk.gov.di.authentication.sharedtest.extensions;

import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SignResult;
import com.amazonaws.services.kms.model.SigningAlgorithmSpec;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.extension.ExtensionContext;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.nio.ByteBuffer;
import java.util.Optional;

public class TokenSigningExtension extends KmsKeyExtension {

    private KmsConnectionService kmsConnectionService;

    public TokenSigningExtension() {
        super("token-signing-key");
    }

    public TokenSigningExtension(String keyAliasSuffix) {
        super(keyAliasSuffix);
    }

    @Override
    public void beforeAll(ExtensionContext context) {
        super.beforeAll(context);
        kmsConnectionService =
                new KmsConnectionService(Optional.of(LOCALSTACK_ENDPOINT), REGION, getKeyAlias());
    }

    public SignedJWT signJwt(JWTClaimsSet claimsSet) {
        try {
            JWSHeader jwsHeader =
                    new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(getKeyAlias()).build();
            Base64URL encodedHeader = jwsHeader.toBase64URL();
            Base64URL encodedClaims = Base64URL.encode(claimsSet.toString());
            String message = encodedHeader + "." + encodedClaims;
            ByteBuffer messageToSign = ByteBuffer.wrap(message.getBytes());
            SignRequest signRequest = new SignRequest();
            signRequest.setMessage(messageToSign);
            signRequest.setKeyId(getKeyAlias());
            signRequest.setSigningAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256.toString());
            SignResult signResult = kmsConnectionService.sign(signRequest);
            String signature =
                    Base64URL.encode(
                                    ECDSA.transcodeSignatureToConcat(
                                            signResult.getSignature().array(),
                                            ECDSA.getSignatureByteArrayLength(JWSAlgorithm.ES256)))
                            .toString();
            return SignedJWT.parse(message + "." + signature);
        } catch (java.text.ParseException | JOSEException e) {
            throw new RuntimeException(e);
        }
    }
}
