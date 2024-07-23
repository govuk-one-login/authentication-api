import { RedisClientType } from "@redis/client";
import { createClient } from "redis";
import { Session } from "../types/session";

let singletonClient: RedisClientType;

export const getRedisClient = async (): Promise<RedisClientType> => {
  const client =
    singletonClient ??
    (await createClient({
      url: "redis://redis-local:6379",
    }).connect());
  singletonClient = client;
  return client;
};

export const getSession = async (sessionId: string) => {
  const client = await getRedisClient();
  const sessionString = await client.get(sessionId);
  if (sessionString == null) {
    throw new Error("No existing session found");
  }
  const session: Session = JSON.parse(sessionString);
  return session;
};
