package uk.gov.di.orchestration.shared.validation;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientCredentialsSelector;
import com.nimbusds.oauth2.sdk.auth.verifier.Context;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.ClientID;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

public class PrivateKeyJwtAuthPublicKeySelector implements ClientCredentialsSelector<String> {
    private final String publicKey;
    private final KeyType keyType;

    public PrivateKeyJwtAuthPublicKeySelector(String publicKey, KeyType keyType) {
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
        byte[] decodedKey = Base64.getMimeDecoder().decode(publicKey);
        try {
            X509EncodedKeySpec ecPublicKeySpec = new X509EncodedKeySpec(decodedKey);
            KeyFactory kf = KeyFactory.getInstance(keyType.getValue());
            return Collections.singletonList(kf.generatePublic(ecPublicKeySpec));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new InvalidClientException(e.getMessage());
        }
    }
}
