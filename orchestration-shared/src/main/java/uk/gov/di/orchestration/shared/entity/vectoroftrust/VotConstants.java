package uk.gov.di.orchestration.shared.entity.vectoroftrust;

import java.util.List;
import java.util.Set;

public class VotConstants {
    // VoT Authentication Components
    public static final VotComponent<AuthId> AUTH_EMPTY = VotComponent.empty(AuthId.class);
    public static final VotComponent<AuthId> AUTH_LOW_LEGACY = VotComponent.of(AuthId.CL);
    public static final VotComponent<AuthId> AUTH_LOW = VotComponent.of(AuthId.C1);
    public static final VotComponent<AuthId> AUTH_MEDIUM_LEGACY = VotComponent.of(AuthId.CL, AuthId.CM);
    public static final VotComponent<AuthId> AUTH_MEDIUM = VotComponent.of(AuthId.C2);
    public static final VotComponent<AuthId> AUTH_HIGH = VotComponent.of(AuthId.C3);
    public static final VotComponent<AuthId> AUTH_VERY_HIGH = VotComponent.of(AuthId.C4);

    // VoT Identity Components
    public static final VotComponent<IdentId> IDENT_EMPTY = VotComponent.empty(IdentId.class);
    public static final VotComponent<IdentId> IDENT_NONE = VotComponent.of(IdentId.P0);
    public static final VotComponent<IdentId> IDENT_LOW = VotComponent.of(IdentId.P1);
    public static final VotComponent<IdentId> IDENT_MEDIUM = VotComponent.of(IdentId.P2);
    public static final VotComponent<IdentId> IDENT_HIGH = VotComponent.of(IdentId.P3);
    public static final VotComponent<IdentId> IDENT_VERY_HIGH = VotComponent.of(IdentId.P4);
    public static final VotComponent<IdentId> IDENT_HMRC200 = VotComponent.of(IdentId.PCL200);
    public static final VotComponent<IdentId> IDENT_HMRC250 = VotComponent.of(IdentId.PCL250);

    // VoT Component Validation Sets
    public static final Set<VotComponent<AuthId>> AUTH_VALID_SET = Set.of(
            AUTH_EMPTY,
            AUTH_LOW,
            AUTH_LOW_LEGACY,
            AUTH_MEDIUM,
            AUTH_HIGH,
            AUTH_VERY_HIGH
    );

    public static final Set<VotComponent<IdentId>> IDENT_VALID_SET = Set.of(
            IDENT_EMPTY,
            IDENT_NONE,
            IDENT_LOW,
            IDENT_MEDIUM,
            IDENT_HIGH,
            IDENT_VERY_HIGH,
            IDENT_HMRC200,
            IDENT_HMRC250
    );

    public static final Set<VotComponent<AuthId>> AUTH_SUPPORTED_SET = Set.of(
            AUTH_EMPTY,
            AUTH_LOW,
            AUTH_LOW_LEGACY,
            AUTH_MEDIUM
    );

    public static final Set<VotComponent<IdentId>> IDENT_SUPPORTED_SET = Set.of(
            IDENT_EMPTY,
            IDENT_NONE,
            IDENT_MEDIUM,
            IDENT_HMRC200,
            IDENT_HMRC250
    );

    // VoT Component Equivalency Lists
    // Note: The first component in each equivalency list is the one that will be chosen when normalising a VoT. These
    // defaults are currently set to legacy components where they exist for compatibility with authentication team.
    public static final List<List<VotComponent<AuthId>>> AUTH_EQUIVALENCY_LIST = List.of(
            List.of(AUTH_MEDIUM_LEGACY, AUTH_MEDIUM, AUTH_EMPTY),
            List.of(AUTH_LOW_LEGACY, AUTH_LOW));

    public static final List<List<VotComponent<IdentId>>> IDENT_EQUIVALENCY_LIST = List.of(
            List.of(IDENT_NONE, IDENT_EMPTY)
    );

    // Threshold VoTs
    public static final VectorOfTrust MAX_AUTH_ONLY_VOT = new VectorOfTrust(AUTH_VERY_HIGH, IDENT_NONE);
    public static final VectorOfTrust MIN_AUTH_IPVC_VOT = new VectorOfTrust(AUTH_MEDIUM, IDENT_LOW);
}
