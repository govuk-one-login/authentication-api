package uk.gov.di.orchestration.shared.utils;

import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;

import java.util.List;

public class VtrListUtils {
    private VtrListUtils() {}

    public static String getVtrLocsAsCommaSeparatedString(List<VectorOfTrust> vtrList) {
        List<VectorOfTrust> orderedVtrList = VectorOfTrust.orderVtrList(vtrList);
        StringBuilder strBuilder = new StringBuilder();
        for (VectorOfTrust vtr : orderedVtrList) {
            String loc =
                    vtr.containsLevelOfConfidence()
                            ? vtr.getLevelOfConfidence().getValue()
                            : LevelOfConfidence.NONE.getValue();
            strBuilder.append(loc).append(",");
        }
        if (!strBuilder.isEmpty()) {
            strBuilder.setLength(strBuilder.length() - 1);
            return strBuilder.toString();
        }
        return "";
    }
}
