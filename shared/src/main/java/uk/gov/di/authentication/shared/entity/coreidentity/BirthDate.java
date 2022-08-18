package uk.gov.di.authentication.shared.entity.coreidentity;

import com.google.gson.annotations.Expose;

public class BirthDate {
    @Expose
    private String value;

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }

        if (!(o instanceof BirthDate)) {
            return false;
        }

        return this.value.equals(((BirthDate)o).getValue());
    }

    @Override
    public String toString() {
        return "BirthDate(value=" + value + ")";
    }
}
