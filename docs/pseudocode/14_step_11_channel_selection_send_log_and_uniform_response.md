# Step 11: Channel Selection, Send, Log and Uniform Response

Source: `docs/sms_validation_process.md`, section "Step 11: Channel Selection, Send, Log and Uniform Response".

Implemented in: `src/otp_guard/pipeline.py: Pipeline.step1_session, SessionService`

```
// Pseudocode for Validation Step 11
function logAndSend(request, providerConfig):
    channel = selectChannel(request.tier, request)
    if channel is null:
        return uniformResponse()             // downgrade with no channel: silently dropped

    logId = addSmsHistoryToDatabase({
        "source": request.source, "phone_number": request.mobile,
        "headers": jsonEncode(request.headers), "content": request.text,
        "sms_provider": providerConfig.provider if channel == "sms" else null,
        "channel": channel, "trusted_platform": request.trustedPlatform,
        "risk_score": request.riskScore, "signals": request.signals, "tier": request.tier,
        "operating_mode": operatingMode(), "session_id": request.sessionId,
        "fingerprint": request.fingerprint, "ip": request.ip, "asn": request.ipInfo.asn
    })

    if channel == "sms":
        redis.incr("global:sms:count:" + currentHour())
        redis.incrby("global:sms:spend:" + currentHour(), request.prefix.costUnits)
        delay = 0 if request.tier == "allow" else min(5 * 2 ** previousSessionRequests(request.sessionId), 60)
        enqueueSend(providerConfig.provider, request.mobile, request.text, logId, delay)
    else:
        enqueueSend(channel, request.mobile, request.text, logId, 0)

    recordSent(request)                      // increments `sent` on every reputation key
    scheduleVerificationTimeout(logId, 600)  // feedback loop: unverified after 10 min counts as failed
    return uniformResponse()
```
