package uk.gov.di.orchestration.shared.extensions.java.lang.Enum;

import manifold.ext.rt.api.Extension;
import manifold.ext.rt.api.ThisClass;

import java.util.Arrays;
import java.util.Optional;

@Extension
public class EnumExt {
    public static <E extends Enum<E>> Optional<E> tryParse(
            @ThisClass Class<E> enumClass, String str) {
        return Arrays.stream(enumClass.getEnumConstants())
                .filter(e -> e.toString().equals(str))
                .findFirst();
    }
}
