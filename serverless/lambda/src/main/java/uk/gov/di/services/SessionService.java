package uk.gov.di.services;

import com.amazonaws.services.lambda.runtime.LambdaLogger;
import uk.gov.di.entity.Session;

public class SessionService {

    public Session createSession() {
        return new Session();
    }

    public void save(Session session, LambdaLogger logger) {
        try (RedisConnectionService redis = new RedisConnectionService(logger)) {
            redis.saveSession(session);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
