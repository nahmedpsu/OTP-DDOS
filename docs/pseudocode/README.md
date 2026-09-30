# Pseudocode

Extracted from [`docs/sms_validation_process.md`](../sms_validation_process.md) by
`scripts/extract_pseudocode.py`. Do not edit these files by hand; edit the design and re-run.

| Section | File | Implemented in |
|---|---|---|
| Atomic RateLimit | [`01_atomic_ratelimit.md`](01_atomic_ratelimit.md) | `src/otp_guard/store.py: LUA_TRY_ACQUIRE, LUA_TRY_ACQUIRE_ALL, RateLimit, MemoryStore.try_acquire*, RedisStore.try_acquire*` |
| Reputation Store | [`02_reputation_store.md`](02_reputation_store.md) | `src/otp_guard/reputation.py: ReputationStore.conversion_ratio` |
| Step 0: Connection and Client Integrity | [`03_step_0_connection_and_client_integrity.md`](03_step_0_connection_and_client_integrity.md) | `src/otp_guard/pipeline.py: Pipeline.establish_trusted_platform, Pipeline.step0_connection_and_client_integrity` |
| Step 1: Client Session Token and Fingerprint | [`04_step_1_client_session_token_and_fingerprint.md`](04_step_1_client_session_token_and_fingerprint.md) | `src/otp_guard/pipeline.py: Pipeline.step1_session, SessionService` |
| Step 2: IP, Subnet and ASN Throttling | [`05_step_2_ip_subnet_and_asn_throttling.md`](05_step_2_ip_subnet_and_asn_throttling.md) | `src/otp_guard/pipeline.py: Pipeline.step2_network_throttles` |
| Step 3: Google reCAPTCHA Validation | [`06_step_3_google_recaptcha_validation.md`](06_step_3_google_recaptcha_validation.md) | `src/otp_guard/pipeline.py: Pipeline.step3_recaptcha` |
| Step 4: HTTP Origin Validation | [`07_step_4_http_origin_validation.md`](07_step_4_http_origin_validation.md) | `src/otp_guard/pipeline.py: Pipeline.step4_origin` |
| Step 5: Number Intelligence | [`08_step_5_number_intelligence.md`](08_step_5_number_intelligence.md) | `src/otp_guard/pipeline.py: Pipeline.step5_number, NumberTracker` |
| Step 6: SMS Text Validation | [`09_step_6_sms_text_validation.md`](09_step_6_sms_text_validation.md) | `src/otp_guard/pipeline.py: Pipeline.step6_text` |
| Step 7: Risk Score Engine and Tier Decision | [`10_step_7_risk_score_engine_and_tier_decision.md`](10_step_7_risk_score_engine_and_tier_decision.md) | `src/otp_guard/pipeline.py: Pipeline.compute_risk_score, Pipeline.decide_tier, Pipeline.step7_risk` |
| Step 8: Per-Number Rate Limit with Progressive Backoff | [`11_step_8_per_number_rate_limit_with_progressive_backoff.md`](11_step_8_per_number_rate_limit_with_progressive_backoff.md) | `src/otp_guard/pipeline.py: Pipeline.step8_per_number` |
| Step 9: Adaptive Rate Limits per Source, Platform and Country | [`12_step_9_adaptive_rate_limits_per_source_platform_and_country.md`](12_step_9_adaptive_rate_limits_per_source_platform_and_country.md) | `src/otp_guard/pipeline.py: Pipeline.effective_limit, Pipeline.step9_source_limits; src/otp_guard/reputation.py: AdaptiveLimits` |
| Step 10: Global Circuit Breaker | [`13_step_10_global_circuit_breaker.md`](13_step_10_global_circuit_breaker.md) | `src/otp_guard/pipeline.py: Pipeline.step1_session, SessionService` |
| Step 11: Channel Selection, Send, Log and Uniform Response | [`14_step_11_channel_selection_send_log_and_uniform_response.md`](14_step_11_channel_selection_send_log_and_uniform_response.md) | `src/otp_guard/pipeline.py: Pipeline.step1_session, SessionService` |
| Verification Feedback Loop (asynchronous) | [`15_verification_feedback_loop_asynchronous.md`](15_verification_feedback_loop_asynchronous.md) | `src/otp_guard/feedback.py: FeedbackLoop` |
| Full Pipeline | [`16_full_pipeline.md`](16_full_pipeline.md) | `src/otp_guard/pipeline.py: Pipeline._process, Pipeline.process` |
