# Atomic RateLimit

Source: `docs/sms_validation_process.md`, section "Atomic RateLimit".

Implemented in: `src/otp_guard/store.py: LUA_TRY_ACQUIRE, LUA_TRY_ACQUIRE_ALL, RateLimit, MemoryStore.try_acquire*, RedisStore.try_acquire*`

```
// RateLimit.tryAcquire(): returns true and consumes one slot, or false without consuming
// Executed atomically inside Redis (EVAL)
LUA_TRY_ACQUIRE = """
    local current = redis.call('INCR', KEYS[1])
    if current == 1 then
        redis.call('EXPIRE', KEYS[1], ARGV[2])
    end
    if current > tonumber(ARGV[1]) then
        redis.call('DECR', KEYS[1])          -- do not consume the slot
        return 0
    end
    return 1
"""

class RateLimit:
    setLimit(maxCount, windowSeconds)
    setKey(key)
    setIdentifier(identifier)

    tryAcquire():
        return redis.eval(LUA_TRY_ACQUIRE, [key + ":" + identifier], [maxCount, windowSeconds]) == 1

    // Read-only helper used by the risk engine
    currentCount():
        return int(redis.get(key + ":" + identifier) or 0)
```
