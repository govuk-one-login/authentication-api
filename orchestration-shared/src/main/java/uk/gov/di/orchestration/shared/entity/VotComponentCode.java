package uk.gov.di.orchestration.shared.entity;

import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.text.MessageFormat.format;

public abstract class VotComponentCode<E extends Enum<E>> {

    private Set<E> componentIds;

    protected VotComponentCode(EnumSet<E> componentIds) {
        this.componentIds = Collections.unmodifiableSet(componentIds);
    }

    protected static <T extends Enum<T>> EnumSet<T> parse(Class<T> enumClass, String code) {
        EnumSet<T> componentIds = EnumSet.noneOf(enumClass);

        if (!code.isEmpty()) {
            for (var idStr : code.split("\\.", -1)) {
                var id = tryParseId(enumClass, idStr);
                if (id.isPresent()) {
                    componentIds.add(id.get());
                    continue;
                }

                throw new IllegalArgumentException(
                        format("Unknown ID \"{0}\" in VoT Component Code \"{1}\".", idStr, code));
            }
        }

        return componentIds;
    }

    public static <E extends Enum<E>> Optional<E> tryParseId(Class<E> enumClass, String id) {
        return Arrays.stream(enumClass.getEnumConstants())
                .filter(e -> e.toString().equals(id))
                .findFirst();
    }

    public Stream<E> stream() {
        return componentIds.stream();
    }

    @Override
    public String toString() {
        return componentIds.stream().map(E::toString).collect(Collectors.joining("."));
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof VotComponentCode<?> other) {
            return componentIds.equals(other.componentIds);
        }

        return false;
    }

    @Override
    public int hashCode() {
        return componentIds.hashCode();
    }
}
