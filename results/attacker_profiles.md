# Attacker profiles

Every profile run by `scripts/run_evaluation.py`, by catalogue. Per-seed randomisation (`runner.randomised`) varies the pool size, the rate and the CAPTCHA class within the profile's allowed classes; the robustness study draws rates and pools from the held-out ranges in `config/evaluation_protocol.json`.

## ATTACKERS (main study)

| Profile | network | fp_mode | numbers | n_blocks | verify_fraction | verify_delay_s | verify_policy | solves_challenges | platform_spoof | trust_building_minutes | fake_failed_receipts | earns_revenue | captcha_classes | Description |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `naive_single_client` | single_ip | single | random | 3 | 0.0 | 1.0 | fixed | False | False | 0 | False | False | ('basic_bot', 'headless_browser') | One IP, one session, random numbers, basic bot captcha |
| `datacenter_rotation` | datacenter | fresh | random | 3 | 0.0 | 1.0 | fixed | False | False | 0 | False | False | ('basic_bot', 'headless_browser', 'captcha_farm') | Hosting ASN abroad, fresh fingerprint per request, headless-browser captcha |
| `residential_bot` | residential | fresh | random | 3 | 0.0 | 1.0 | fixed | False | False | 0 | False | False | ('basic_bot', 'headless_browser') | Residential pool in-country, fresh fingerprint, basic or headless-browser captcha |
| `residential_captcha_farm` | residential | fresh | random | 3 | 0.0 | 1.0 | fixed | False | False | 0 | False | False | ('captcha_farm',) | Residential pool, fresh fingerprint, farmed captcha (human-like scores) |
| `residential_aged_fps` | residential | aged | random | 3 | 0.0 | 1.0 | fixed | False | False | 0 | False | False | ('captcha_farm',) | Residential pool, unique fingerprints pre-aged 2 h, farmed captcha |
| `residential_reused_profile` | residential | reused | random | 3 | 0.0 | 1.0 | fixed | False | False | 0 | False | False | ('captcha_farm',) | Residential pool, one 48 h old browser profile reused |
| `sequential_numbers` | residential | fresh | sequential | 3 | 0.0 | 1.0 | fixed | False | False | 0 | False | False | ('captcha_farm',) | Residential pool, numbers walked upward |
| `premium_pumping` | residential | fresh | premium | 3 | 0.0 | 1.0 | fixed | False | False | 0 | False | True | ('captcha_farm',) | Residential pool, premium-rate prefix |
| `spoofed_platform` | residential | fresh | random | 3 | 0.0 | 1.0 | fixed | False | True | 0 | False | False | ('captcha_farm',) | Residential pool, HTTP_PLATFORM: ios without attestation; valid host and session (only the header is spoofed) |

## ADAPTIVE_ATTACKERS

| Profile | network | fp_mode | numbers | n_blocks | verify_fraction | verify_delay_s | verify_policy | solves_challenges | platform_spoof | trust_building_minutes | fake_failed_receipts | earns_revenue | captcha_classes | Description |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `pumper_verifies_instantly` | residential | aged | elevated | 3 | 1.0 | 1.0 | fixed | False | False | 0 | False | True | ('captcha_farm',) | Colluding carrier on the elevated range submits every code within 1 s (conversion 100 %) |
| `pumper_verifies_humanlike` | residential | aged | elevated | 3 | 0.6 | 30.0 | fixed | False | False | 0 | False | True | ('captcha_farm',) | Colluding carrier submits 60 % of codes after 30 s (looks like real conversion) |
| `pumper_standard_range_humanlike` | residential | aged | random | 3 | 0.6 | 30.0 | fixed | False | False | 0 | False | False | ('captcha_farm',) | Random numbers across all standard prefixes, 60 % verified after 30 s: a flooder that verifies, not a pumper (it earns nothing) |
| `challenge_solver` | datacenter | fresh | random | 3 | 0.0 | 1.0 | fixed | True | False | 0 | False | False | ('headless_browser', 'captcha_farm') | Datacenter rotation abroad (score lands in the challenge tier) and pays a solving service for every challenge |
| `low_and_slow_20_asns` | multi_asn | aged | random | 3 | 0.0 | 1.0 | fixed | False | False | 0 | False | False | ('captcha_farm',) | 2 requests/min spread over 20 residential ASNs, aged fingerprints, under legitimate volume |
| `trust_building_pumper` | residential | aged | random | 3 | 0.0 | 1.0 | fixed | False | False | 10 | False | True | ('captcha_farm',) | Builds trust first: 500 identities and numbers verify everything (human-like delay) for 10 minutes, then the same identities flood without verifying, so verified-history exemptions and trusted numbers work in its favour |
| `trust_building_concentrated` | residential | aged | concentrated | 3 | 0.0 | 1.0 | fixed | False | False | 10 | False | True | ('captcha_farm',) | Same preparation (500 identity/number pairs verify everything for 10 minutes), but the numbers lie in 3 destination blocks the carrier terminates, so the block memory is what the flood phase must get past |
| `trust_building_long` | residential | aged | random | 3 | 0.0 | 1.0 | fixed | False | False | 30 | False | True | ('captcha_farm',) | Trust building for 30 minutes (500 identity/number pairs verify everything), then 30 minutes of flood with the same pairs |
| `threshold_aware_carrier` | residential | aged | concentrated | 3 | 0.0 | 100.0 | threshold_aware | False | False | 0 | False | True | ('captcha_farm',) | Concentrated pumper on 3 blocks whose carrier knows the deployed test parameters and the worker's timing, replays its own pending outcomes in the order the deployment applies them, and enters a code (100 s after delivery) only when not doing so would bring its block within 1 log unit of the threshold |
| `receipt_faking_carrier` | residential | aged | concentrated | 3 | 0.0 | 1.0 | fixed | False | False | 0 | True | True | ('captcha_farm',) | Concentrated pumper whose carrier reports every delivery as failed: the sends are billed but feed no block test |
| `block_poisoner` | residential | aged | poison | 3 | 0.0 | 1.0 | fixed | False | False | 0 | False | False | ('captcha_farm',) | Floods the destination blocks that real users concentrate on, to get them a verdict (collateral-damage attack) |
| `low_and_slow_below_dilution` | multi_asn | aged | random | 3 | 0.0 | 1.0 | fixed | False | False | 0 | False | False | ('captcha_farm',) | 10 requests/min over 20 ASNs against 20/min legitimate: under the 1.8x dilution bound |

## PUMPING_ATTACKERS

| Profile | network | fp_mode | numbers | n_blocks | verify_fraction | verify_delay_s | verify_policy | solves_challenges | platform_spoof | trust_building_minutes | fake_failed_receipts | earns_revenue | captcha_classes | Description |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `concentrated_pumper_no_verify` | residential | aged | concentrated | 3 | 0.0 | 1.0 | fixed | False | False | 0 | False | True | ('captcha_farm',) | Pumper on 3 destination blocks of 10 000 numbers inside a standard prefix; aged fingerprints, farmed captcha; carrier does not verify |
| `concentrated_pumper_verifies_instantly` | residential | aged | concentrated | 3 | 1.0 | 1.0 | fixed | False | False | 0 | False | True | ('captcha_farm',) | Same blocks; the carrier submits every code within 1 s |
| `concentrated_pumper_verifies_humanlike` | residential | aged | concentrated | 3 | 0.6 | 30.0 | fixed | False | False | 0 | False | True | ('captcha_farm',) | Same blocks; the carrier submits 60 % of codes after 30 s |
| `concentrated_pumper_solves_challenges` | residential | aged | concentrated | 3 | 0.0 | 1.0 | fixed | True | False | 0 | False | True | ('captcha_farm',) | Same blocks, carrier does not verify; the pumper buys a solution for every interactive challenge |

25 named profiles. The spread sweep adds 18 generated `spread_<ranges>x<digits>` pumpers and the dilution study runs `residential_captcha_farm` at five rate multiples.
