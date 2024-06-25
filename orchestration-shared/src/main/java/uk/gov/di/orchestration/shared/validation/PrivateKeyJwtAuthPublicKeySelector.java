package uk.gov.di.orchestration.shared.validation;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientCredentialsSelector;
import com.nimbusds.oauth2.sdk.auth.verifier.Context;
import com.nimbusds.oauth2.sdk.id.ClientID;

import java.security.PublicKey;
import java.util.Collections;
import java.util.List;

public class PrivateKeyJwtAuthPublicKeySelector implements ClientCredentialsSelector<String> {
    private final PublicKey publicKey;

    public PrivateKeyJwtAuthPublicKeySelector(PublicKey publicKey) {
        this.publicKey = publicKey;
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
            Context<String> context) {
        return Collections.singletonList(publicKey);
    }
}
