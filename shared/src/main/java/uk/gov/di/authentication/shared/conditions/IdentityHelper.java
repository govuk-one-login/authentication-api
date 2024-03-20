package uk.gov.di.authentication.shared.conditions;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.List;
import java.util.Map;
import java.util.Objects;

import static uk.gov.di.authentication.shared.entity.LevelOfConfidence.NONE;

public class IdentityHelper {

    private IdentityHelper() {}

    public static boolean identityRequired(
            boolean identityRequired,
            boolean clientSupportsIdentityVerification,
            boolean identityEnabled) {
        return clientSupportsIdentityVerification && identityEnabled && identityRequired;
    }
}
