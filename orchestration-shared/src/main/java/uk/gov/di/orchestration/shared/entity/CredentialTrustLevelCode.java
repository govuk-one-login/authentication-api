package uk.gov.di.orchestration.shared.entity;

import com.google.gson.annotations.JsonAdapter;
import uk.gov.di.orchestration.shared.serialization.CredentialTrustLevelCodeAdapter;

import java.util.EnumSet;

/** Code Representing a {@link CredentialTrustLevel} */
@JsonAdapter(CredentialTrustLevelCodeAdapter.class)
public class CredentialTrustLevelCode extends VotComponentCode<CredentialTrustLevelId> {

    public static final CredentialTrustLevelCode CL =
            CredentialTrustLevelCode.of(CredentialTrustLevelId.CL);
    public static final CredentialTrustLevelCode CL_CM =
            CredentialTrustLevelCode.of(CredentialTrustLevelId.CL, CredentialTrustLevelId.CM);
    public static final CredentialTrustLevelCode C1 =
            CredentialTrustLevelCode.of(CredentialTrustLevelId.C1);
    public static final CredentialTrustLevelCode C2 =
            CredentialTrustLevelCode.of(CredentialTrustLevelId.C2);

    public CredentialTrustLevelCode(EnumSet<CredentialTrustLevelId> ids) {
        super(ids);
    }

    private static <E extends Enum<E>> CredentialTrustLevelCode of(
            CredentialTrustLevelId first, CredentialTrustLevelId... rest) {
        return new CredentialTrustLevelCode(EnumSet.of(first, rest));
    }

    public static CredentialTrustLevelCode parse(String code) {
        return new CredentialTrustLevelCode(
                VotComponentCode.parse(CredentialTrustLevelId.class, code));
    }
}
