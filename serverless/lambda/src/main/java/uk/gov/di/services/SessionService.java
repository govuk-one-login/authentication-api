package uk.gov.di.services;

import io.lettuce.core.RedisClient;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.api.sync.RedisStringCommands;
import uk.gov.di.entity.Session;

public class SessionService {
    public Session createSession() {
        return new Session();
    }

    public void save(Session session) {
        RedisClient client = RedisClient.create("redis://test-sessions-store.rixhjg.ng.0001.euw2.cache.amazonaws.com:6379");
        StatefulRedisConnection<String, String> connection = client.connect();
        RedisStringCommands<String, String> sync = connection.sync();
        sync.set(session.getSessionId(), "???");
    }
}
