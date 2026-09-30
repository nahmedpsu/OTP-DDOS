"""Published figures the synthetic traffic is calibrated to. Every number here is a published
list price or a published measurement, with its source, or is marked ASSUMED. No production
logs were available for this evaluation (see docs/evaluation.md, Limitations)."""

CALIBRATION = {
    "sms_unit_cost_usd": {
        "value": 0.1422, "unit": "USD per outbound SMS to Saudi Arabia",
        "source": "Twilio SMS pricing, Saudi Arabia, https://www.twilio.com/en-us/sms/pricing/sa"},
    "hlr_lookup_cost_usd": {
        "value": 0.008, "unit": "USD per Line Type Intelligence lookup",
        "source": "Twilio Lookup pricing, https://www.twilio.com/en-us/lookup/pricing"},
    "recaptcha_cost_usd": {
        "value": 0.001, "unit": "USD per assessment beyond the free tier",
        "source": "reCAPTCHA Enterprise billing, https://docs.cloud.google.com/recaptcha/docs/billing-information"},
    "legit_conversion": {
        "value": 0.80, "unit": "fraction of legitimate OTP sends that are verified",
        "source": "Twilio reports a 65 %+ global SMS OTP conversion rate; well-run flows sit higher. "
                  "0.80 is ASSUMED within that range. https://www.twilio.com/en-us/blog/validate-measure-success-verify-implementation"},
    "legit_verify_delay_s": {
        "value": {"lognormal_median_s": 25, "sigma": 0.6}, "unit": "seconds from send to code entry",
        "source": "SMS delivery is typically 2 to 5 s and 67 % of users abandon if the code takes over 30 s; "
                  "a median of 25 s with lognormal spread is ASSUMED to match. "
                  "https://www.messagecentral.com/blog/customizable-otp-timeouts"},
    "recaptcha_threshold": {
        "value": 0.5, "unit": "score",
        "source": "Google's documented default, https://developers.google.com/recaptcha/docs/v3"},
    "recaptcha_human_scores": {
        "value": {"beta_a": 9, "beta_b": 1.5}, "unit": "Beta distribution of v3 scores for humans (mean 0.86)",
        "source": "ASSUMED. Google publishes no distribution; the admin console shows it per site."},
    "recaptcha_bot_scores": {
        "value": {"basic_bot": [2, 5], "headless_browser": [5, 5], "captcha_farm": [9, 1.5]},
        "unit": "Beta(a, b) per bot sophistication (means 0.29, 0.50, 0.86)",
        "source": "ASSUMED. Solving services sell v3 tokens at 0.3 to 5 USD per 1000, so a farmed score "
                  "distribution equal to humans is the conservative choice. https://research.aimultiple.com/captcha-solving-services"},
    "captcha_solve_cost_usd": {
        "value": 0.003, "unit": "USD per solved reCAPTCHA v3 token",
        "source": "2.89 USD per 1000 (EndCaptcha) to 5 USD per 1000 (2Captcha) for v3; "
                  "https://research.aimultiple.com/captcha-solving-services"},
    "residential_proxy_cost_per_gb_usd": {
        "value": 3.0, "unit": "USD per GB",
        "source": "Entry prices 1 to 8 USD per GB across major providers in 2025, "
                  "https://www.techradar.com/features/cheapest-proxy-servers"},
    "residential_proxy_pool_size": {
        "value": {"min": 30_000_000, "max": 400_000_000}, "unit": "IPs in the largest pools",
        "source": "Bright Data 400M+, Oxylabs 175M+, IPRoyal 32M+; https://www.joinmassive.com/blog/best-residential-proxy-providers"},
    "request_bytes": {
        "value": 6_000, "unit": "bytes per OTP request round trip through a proxy",
        "source": "ASSUMED (TLS handshake plus a small JSON body)."},
    "pumping_revenue_share": {
        "value": {"low": 0.2, "high": 0.5}, "unit": "fraction of the termination fee paid to the fraudster",
        "source": "ASSUMED range. Public reports describe a share of the termination fee without a figure; "
                  "https://cybelangel.com/blog/sms-pumping-fraud-telecom-attack/ , "
                  "https://www.ericsson.com/en/reports-and-papers/white-papers/ait-the-root-cause-the-solution-and-the-implication-on-rcs-and-network-apis"},
    "cgnat_prevalence_mobile": {
        "value": 0.94, "unit": "fraction of mobile data networks deploying CGN",
        "source": "Richter et al., A Multi-perspective Analysis of Carrier-Grade NAT Deployment, https://arxiv.org/pdf/1605.05606"},
    "legit_traffic_rate_per_min": {
        "value": 20, "unit": "legitimate OTP requests per minute at the source under test",
        "source": "ASSUMED; scaled in the low-and-slow study."},
    "legit_fresh_fingerprint_fraction": {
        "value": 0.6, "unit": "fraction of legitimate sign-ups from a browser never seen before",
        "source": "ASSUMED (sign-up traffic is mostly new visitors)."},
}


def value(key):
    return CALIBRATION[key]["value"]
