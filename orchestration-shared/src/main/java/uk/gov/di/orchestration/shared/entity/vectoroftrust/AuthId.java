package uk.gov.di.orchestration.shared.entity.vectoroftrust;

/**
 * Enum representing credential authentication IDs. Note not all IDs correspond to an authentication level i.e. "Cm"
 */
public enum AuthId {
    CL("Cl"),
    CM("Cm"),
    C1("C1"),
    C2("C2"),
    C3("C3"),
    C4("C4");

    private final String value;

    AuthId(String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return value;
    }
}
