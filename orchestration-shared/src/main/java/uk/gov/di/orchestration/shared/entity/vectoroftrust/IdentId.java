package uk.gov.di.orchestration.shared.entity.vectoroftrust;

/**
 * Enum representing identity validation IDs.
 */
public enum IdentId {
    P0("P0"),
    PCL200("PCL200"),
    PCL250("PCL250"),
    P1("P1"),
    P2("P2"),
    P3("P3"),
    P4("P4");

    private final String value;

    IdentId(String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return value;
    }
}
