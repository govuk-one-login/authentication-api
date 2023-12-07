package uk.gov.di.orchestration.sharedtest.helper;

import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.reflections.Reflections;

import java.util.Arrays;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.reflections.scanners.Scanners.SubTypes;

public class DynatraceHelper {
    private static final ClassLoader loader = ClassLoader.getSystemClassLoader();

    public static void assertHandlersHaveOwnHandleRequestMethods(String packageName) {
        getHandlers(packageName).forEach(DynatraceHelper::assertHasOwnHandleRequestMethod);
    }

    private static Stream<String> getHandlers(String packageName) {
        return new Reflections(packageName).get(SubTypes.of(RequestHandler.class)).stream();
    }

    private static void assertHasOwnHandleRequestMethod(String className) {
        try {
            var methods = loader.loadClass(className).getDeclaredMethods();
            var handleRequestMethods =
                    Arrays.stream(methods).filter(m -> "handleRequest".equals(m.getName())).count();
            assertTrue(
                    handleRequestMethods > 0,
                    className
                            + " does not define a handleRequest method, which is required for Dynatrace");
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
}
