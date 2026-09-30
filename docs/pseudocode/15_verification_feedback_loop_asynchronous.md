# Verification Feedback Loop (asynchronous)

Source: `docs/sms_validation_process.md`, section "Verification Feedback Loop (asynchronous)".

Implemented in: `src/otp_guard/feedback.py: FeedbackLoop`

```
// Pseudocode for the feedback loop
function onOtpVerified(logId):
    send = smsHistory.get(logId)
    for key in reputationKeysOf(send): reputation.incr(key, "verified")
    reputation.markTrusted("num:" + send.phone_number)

function onOtpFailedOrTimeout(logId):
    send = smsHistory.get(logId)
    for key in reputationKeysOf(send):
        reputation.incr(key, "failed")
        r = reputation.get(key)
        resolved = r.verified + r.failed
        if resolved >= 50 and r.verified / resolved < 0.1:
            denylist.add(key, ttl = 86400)
```
