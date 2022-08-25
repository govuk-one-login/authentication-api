package uk.gov.di.authentication.shared.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.coreidentity.BirthDate;
import uk.gov.di.authentication.shared.entity.coreidentity.NameParts;

import java.util.List;

public class CoreIdentity {
    @Expose private List<NameParts> name;

    @Expose
    @SerializedName("birthDate")
    private List<BirthDate> birthDate;

    public List<BirthDate> getBirthDate() {
        return birthDate;
    }

    public void setBirthDate(List<BirthDate> birthDate) {
        this.birthDate = birthDate;
    }

    public List<NameParts> getName() {
        return name;
    }

    public void setName(List<NameParts> name) {
        this.name = name;
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }

        if (!(o instanceof CoreIdentity)) {
            return false;
        }

        return this.birthDate.equals(((CoreIdentity) o).getBirthDate())
                && this.name.equals(((CoreIdentity) o).getName());
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((birthDate == null) ? 0 : birthDate.hashCode());
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        return result;
    }
}
