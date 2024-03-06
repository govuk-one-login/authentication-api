package uk.gov.di.orchestration.shared.entity.vectoroftrust;

import com.google.gson.annotations.JsonAdapter;
import uk.gov.di.orchestration.shared.serialization.LevelOfConfidenceCodeTypeAdapter;

import java.util.EnumSet;

@JsonAdapter(LevelOfConfidenceCodeTypeAdapter.class)
public class LevelOfConfidenceCode extends VotComponentCode<LevelOfConfidenceId> {

    public static final LevelOfConfidenceCode EMPTY = LevelOfConfidenceCode.empty();
    public static final LevelOfConfidenceCode P0 = LevelOfConfidenceCode.of(LevelOfConfidenceId.P0);
    public static final LevelOfConfidenceCode P1 = LevelOfConfidenceCode.of(LevelOfConfidenceId.P1);
    public static final LevelOfConfidenceCode P2 = LevelOfConfidenceCode.of(LevelOfConfidenceId.P2);
    public static final LevelOfConfidenceCode P3 = LevelOfConfidenceCode.of(LevelOfConfidenceId.P3);
    public static final LevelOfConfidenceCode P4 = LevelOfConfidenceCode.of(LevelOfConfidenceId.P4);
    public static final LevelOfConfidenceCode PCL200 =
            LevelOfConfidenceCode.of(LevelOfConfidenceId.PCL200);
    public static final LevelOfConfidenceCode PCL250 =
            LevelOfConfidenceCode.of(LevelOfConfidenceId.PCL250);

    public LevelOfConfidenceCode(EnumSet<LevelOfConfidenceId> ids) {
        super(ids);
    }

    private static LevelOfConfidenceCode empty() {
        return new LevelOfConfidenceCode(EnumSet.noneOf(LevelOfConfidenceId.class));
    }

    private static LevelOfConfidenceCode of(LevelOfConfidenceId id) {
        return new LevelOfConfidenceCode(EnumSet.of(id));
    }

    public static LevelOfConfidenceCode parse(String code) {
        return new LevelOfConfidenceCode(VotComponentCode.parse(LevelOfConfidenceId.class, code));
    }
}
