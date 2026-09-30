# Step 10: Global Circuit Breaker

Source: `docs/sms_validation_process.md`, section "Step 10: Global Circuit Breaker".

Implemented in: `src/otp_guard/pipeline.py: Pipeline.step1_session, SessionService`

```
// Pseudocode for Validation Step 10
function circuitBreaker(request):
    if request.tier not in ["allow", "delay"]:
        return true                          // non-SMS channels do not spend SMS budget

    count = redis.get("global:sms:count:" + currentHour()) or 0
    spend = redis.get("global:sms:spend:" + currentHour()) or 0
    util = max(count / GLOBAL_SMS_PER_HOUR, spend / GLOBAL_SPEND_UNITS_PER_HOUR)

    mode = "emergency" if (util >= 1.0 or SMS_KILL_SWITCH) else "elevated" if util >= 0.8 else "normal"
    setOperatingMode(mode)
    if mode != "normal": alertOnCall("SMS circuit breaker: " + mode, util)

    if SMS_KILL_SWITCH or (mode == "emergency" and request.riskScore >= 10):
        request.tier = "downgrade"           // Step 11 will try a non-SMS channel
    return true
```
