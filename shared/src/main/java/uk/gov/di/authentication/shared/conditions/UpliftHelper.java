package uk.gov.di.authentication.shared.conditions;

import uk.gov.di.authentication.shared.state.UserContext;

public class UpliftHelper {

    public static boolean upliftRequired(UserContext context) {
        return (context.getSession()
                        .getCurrentCredentialStrength()
                        .compareTo(
                                context.getClientSession()
                                        .getEffectiveVectorOfTrust()
                                        .getCredentialTrustLevel())
                < 0);
    }
}
