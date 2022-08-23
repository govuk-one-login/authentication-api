package uk.gov.di.authentication.shared.entity.coreidentity;

import com.google.gson.annotations.Expose;

public class NamePart {
    @Expose private String type;
    @Expose private String value;

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

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

        if (!(o instanceof NamePart)) {
            return false;
        }

        return this.type.equals(((NamePart) o).getType())
                && this.value.equals(((NamePart) o).getValue());
    }

    @Override
    public String toString() {
        return "NamePart(type=" + this.type + ";value=" + this.value + ")";
    }
}
