package uk.gov.di.orchestration.shared.entity.vectoroftrust;

import java.util.EnumSet;

public class VotConstants {
    public static final VotComponent<AuthId> C_EMPTY = VotComponent.empty(AuthId.class);
    public static final VotComponent<AuthId> C_LOW_LEGACY = VotComponent.of(AuthId.CL);
    public static final VotComponent<AuthId> C_LOW = VotComponent.of(AuthId.C1);
    public static final VotComponent<AuthId> C_MEDIUM_LEGACY = VotComponent.of(AuthId.CL, AuthId.CM);
    public static final VotComponent<AuthId> C_MEDIUM = VotComponent.of(AuthId.C2);
    public static final VotComponent<IdentId> P_EMPTY = VotComponent.empty(IdentId.class);
    public static final VotComponent<IdentId> P_NONE = VotComponent.of(IdentId.P0);
    public static final VotComponent<IdentId> P_MEDIUM = VotComponent.of(IdentId.P2);
    public static final VotComponent<IdentId> P_HMRC200 = VotComponent.of(IdentId.PCL200);
    public static final VotComponent<IdentId> P_HMRC250 = VotComponent.of(IdentId.PCL250);

    public static final EnumSet<VotVocabVersion> VOT_VER_1 = EnumSet.of(VotVocabVersion.V1);
    public static final EnumSet<VotVocabVersion> VOT_VER_2 = EnumSet.of(VotVocabVersion.V2);
    public static final EnumSet<VotVocabVersion> VOT_VER_1_2 = EnumSet.of(VotVocabVersion.V1, VotVocabVersion.V2);
    public static final EnumSet<VotVocabVersion> VOT_VER_1_HMRC = EnumSet.of(VotVocabVersion.V1);
    public static final EnumSet<VotVocabVersion> VOT_VER_2_HMRC = EnumSet.of(VotVocabVersion.V2);
    public static final EnumSet<VotVocabVersion> VOT_VER_1_2_HMRC = EnumSet.of(VotVocabVersion.V1, VotVocabVersion.V2);
}
