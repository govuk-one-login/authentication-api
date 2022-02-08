package uk.gov.di.authentication.sharedtest.exceptions;

import java.util.function.Consumer;
import java.util.function.Function;

public class Unchecked {

    @FunctionalInterface
    public interface ThrowingFunction<T, U> {
        U apply(T input) throws Exception;
    }

    @FunctionalInterface
    public interface ThrowingSupplier<T> {
        T get() throws Exception;
    }

    @FunctionalInterface
    public interface ThrowingConsumer<T> {
        void apply(T input) throws Exception;
    }

    @FunctionalInterface
    public interface ThrowingRunnable {
        void run() throws Exception;
    }

    public static <T, U> Function<T, U> unchecked(ThrowingFunction<T, U> function) {
        return t -> {
            try {
                return function.apply(t);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
    }

    public static <T> T unchecked(ThrowingSupplier<T> supplier) {
        try {
            return supplier.get();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static <T> Consumer<T> unchecked(ThrowingConsumer<T> consumer) {
        return t -> {
            try {
                consumer.apply(t);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
    }

    public static void unchecked(ThrowingRunnable runnable) {
        try {
            runnable.run();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
