package uk.gov.di.authentication.shared.validation;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientCredentialsSelector;
import com.nimbusds.oauth2.sdk.auth.verifier.Context;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import uk.gov.di.authentication.shared.exceptions.UncheckedInvalidKeySpecException;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

public class PrivateKeyJwtAuthPublicKeySelector implements ClientCredentialsSelector<String> {
    private final List<String> publicKey;
    private final KeyType keyType;

    public PrivateKeyJwtAuthPublicKeySelector(List<String> publicKey, KeyType keyType) {
        this.publicKey = publicKey;
        this.keyType = keyType;
    }

    @Override
    public List<Secret> selectClientSecrets(
            ClientID claimedClientID,
            ClientAuthenticationMethod authMethod,
            Context<String> context) {
        return Collections.emptyList();
    }

    @Override
    public List<PublicKey> selectPublicKeys(
            ClientID claimedClientID,
            ClientAuthenticationMethod authMethod,
            JWSHeader jwsHeader,
            boolean forceRefresh,
            Context<String> context)
            throws InvalidClientException {
        KeyFactory kf;
        try {
            kf = KeyFactory.getInstance(keyType.getValue());
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidClientException(e.getMessage());
        }

        try {

            return publicKey.stream()
                    .map(key -> Base64.getMimeDecoder().decode(key))
                    .map(X509EncodedKeySpec::new)
                    .map(
                            keySpec -> {
                                try {
                                    return kf.generatePublic(keySpec);
                                } catch (InvalidKeySpecException e) {
                                    throw new UncheckedInvalidKeySpecException(e.getMessage());
                                }
                            })
                    .toList();
        } catch (UncheckedInvalidKeySpecException e) {
            throw new InvalidClientException(e.getMessage());
        }
    }
}
