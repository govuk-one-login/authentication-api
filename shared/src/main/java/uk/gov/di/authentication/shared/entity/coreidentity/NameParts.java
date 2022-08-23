package uk.gov.di.authentication.shared.entity.coreidentity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import java.util.List;

public class NameParts {
    @Expose
    @SerializedName("nameParts")
    private List<NamePart> nameParts;

    public List<NamePart> getNameParts() {
        return nameParts;
    }

    public void setNameParts(List<NamePart> nameParts) {
        this.nameParts = nameParts;
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }

        if (!(o instanceof NameParts)) {
            return false;
        }

        return this.nameParts.equals(((NameParts) o).getNameParts());
    }

    @Override
    public String toString() {
        return "NameParts(" + nameParts.toString() + ")";
    }
}
