package uk.gov.di.authentication.shared.conditions;

import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Objects;

public class UpliftHelper {

    private UpliftHelper() {}

    public static boolean upliftRequired(UserContext context) {
        if (Objects.isNull(context.getSession().getCurrentCredentialStrength())) {
            return false;
        }
        return (context.getSession()
                        .getCurrentCredentialStrength()
                        .compareTo(
                                context.getClientSession()
                                        .getEffectiveVectorOfTrust()
                                        .getCredentialTrustLevel())
                < 0);
    }
}
