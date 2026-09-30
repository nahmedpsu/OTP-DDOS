# SMS Validation Process

## Overview
The SMS validation process consists of 7 steps to ensure security, prevent abuse, and maintain rate limits.

## Validation Steps

### VALIDATION STEP 0: Initial Security Check

Blocks requests from:
- Proxy connections (detected via `check_is_proxy_connection()`)
- Hosts other than 'example.com' unless platform is iOS

**Example:**
- HTTP_HOST: 'someotherhost.com'
- HTTP_PLATFORM: not 'ios'
- check_is_proxy_connection(): true
- Result: Blocked (returns false)

```
// Pseudocode for Validation Step 0
function initialSecurityCheck(host, platform, isProxyConnection):
    if (host != 'example.com' AND platform != 'ios' AND isProxyConnection):
        return false
    return true
    
// Example
host = "randomhost.com"
platform = "web"
isProxy = true // Detected by check_is_proxy_connection()
isAllowed = initialSecurityCheck(host, platform, isProxy)
// isAllowed = false (blocked because it's a proxy connection from non-allowed host)
```

#### VALIDATION STEP 1: Google reCAPTCHA Validation

For web platform requests only:
- Verifies the Google reCAPTCHA token to prevent automated/bot submissions
- Uses `verifyGoogleReCaptcha()` method to validate the token

**Example:**
- Platform: Web
- reCAPTCHA token: "03AGdBq24PBgq8..."
- Result: Allowed if token is valid, blocked otherwise

```
// Pseudocode for Validation Step 1
function validateReCaptcha(post, platform):
    if platform == "Web":
        recaptchaResult = verifyGoogleReCaptcha(post)
        return recaptchaResult['valid']
    else:
        return true // Skip validation for non-web platforms
    
// Example
post = {
    "g-recaptcha-response": "03AGdBq24PBgq8...",
    "other_data": "..."
}
platform = "Web"
isValidCaptcha = validateReCaptcha(post, platform)
// isValidCaptcha = true if reCAPTCHA token is valid
```

##### VALIDATION STEP 2: HTTP Origin Validation

Extracts the domain from the origin and checks if it's in the allowed domains list.
Only requests from allowed domains will be processed.

**Example:**
- Origin: https://app.example.com/send-sms
- Extracted domain: example.com
- Result: Allowed (in allowed_domains list)

```
// Pseudocode for Validation Step 2
function validateHttpOrigin(origin, allowedDomains):
    extractedDomain = extractDomainFromUrl(origin)
    if extractedDomain in allowedDomains:
        return true
    else:
        return false
        
// Example
origin = "https://app.example.com/send-sms"
allowedDomains = ["admin.example.com", "example.com", "api.example.com", "partner.example.com"]
isValidOrigin = validateHttpOrigin(origin, allowedDomains)
// isValidOrigin = true (because example.com is in allowedDomains)
```

###### VALIDATION STEP 3: Mobile Number Country Validation

Checks if the mobile number's country code is in the allowed list.
Skips this validation for bulk SMS.

**Example:**
- Mobile: 966501234567 (Saudi Arabia)
- Result: Allowed if 966 is in the allowed country codes list

```
// Pseudocode for Validation Step 3
function validateMobileCountry(mobile, allowedCountryCodes):
    mobile = removePlusSign(mobile)
    mobile = removeLeadingZeros(mobile)
    countryCode = getFirstThreeDigits(mobile)
    
    // Special case for country code 968 - block from web
    if countryCode == "968" and platform != "ios" and platform != "android":
        return false
        
    return countryCode in allowedCountryCodes
    
// Example
mobile = "+966501234567"
allowedCountryCodes = ["966", "971", "965"] // Example country codes
isValidMobile = validateMobileCountry(mobile, allowedCountryCodes)
// isValidMobile = true (because 966 is in allowedCountryCodes)
```

####### VALIDATION STEP 4: SMS Text Length Validation

Ensures:
- Request is not from test server
- SMS text is not empty
- SMS text doesn't exceed 420 characters (3 units of 140 chars)
- Mobile number is not in the EXCLUDED_NUMBERS list

**Example:**
- SMS Text: "Your verification code is 1234" (28 chars)
- Result: Allowed (under 420 chars)

```
// Pseudocode for Validation Step 4
function validateSmsText(text, isTestServer):
    if isTestServer:
        return true // Skip validation for test server
        
    if length(text) > 0 and length(text) <= 420:
        return true
    else:
        return false
        
// Example
smsText = "Your verification code is 1234. Please enter this code in the app to verify your account."
isTestServer = false
isValidText = validateSmsText(smsText, isTestServer)
// isValidText = true (because text length is under 420 characters)
```

######## VALIDATION STEP 5: Rate Limiting Per Mobile Number

Limits SMS sending to 1 message per 5 seconds for each mobile number.
Uses RateLimit class to track and enforce limits.

**Example:**
- Mobile: 966501234567
- Previous SMS sent: 3 seconds ago
- Result: Rejected (less than 5 seconds since last SMS)

```
// Pseudocode for Validation Step 5
function validateRateLimitPerMobile(mobile):
    rateLimit = new RateLimit()
    rateLimit.setLimit(1, 5) // 1 SMS per 5 seconds
    rateLimit.setKey("send_global_sms:limit")
    rateLimit.setIdentifier(mobile)
    
    if rateLimit.hasExceededLimit():
        return false
    else:
        rateLimit.incrementCount()
        return true
        
// Example
mobile = "966501234567"
canSendSms = validateRateLimitPerMobile(mobile)
// canSendSms = false if another SMS was sent to this number in the last 5 seconds
```

######### VALIDATION STEP 6: Rate Limiting Per Source and Platform

Enforces SMS sending limits based on:
- Source (e.g., App/RegisterOTP)
- Platform (iOS, web, Android)
- Time period (per minute and per hour)

**Example:**
- Source: App/RegisterOTP
- Platform: ios
- Per minute limit: 10 SMS
- Current count: 9 SMS in last minute
- Result: Allowed (under the limit)

```
// Pseudocode for Validation Step 6
function validateSourceRateLimit(source, platform, limits):
    if source not in limits:
        return true // No limits for this source
        
    sourceLimit = limits[source]
    
    // Check per minute limit
    minuteLimit = new RateLimit()
    minuteLimit.setLimit(sourceLimit["per_minute_" + platform], 60)
    minuteLimit.setKey("sms_cap_per_minute_" + platform + ":limit")
    minuteLimit.setIdentifier(source)
    
    if minuteLimit.hasExceededLimit():
        logError(platform + " SMS PerMinute Cap Reached!")
        return false
    
    minuteLimit.incrementCount()
    
    // Check per hour limit
    hourLimit = new RateLimit()
    hourLimit.setLimit(sourceLimit["per_hour_" + platform], 3600)
    hourLimit.setKey("sms_cap_per_hour_" + platform + ":limit")
    hourLimit.setIdentifier(source)
    
    if hourLimit.hasExceededLimit():
        logError(platform + " SMS PerHour Cap Reached!")
        return false
    
    hourLimit.incrementCount()
    return true
    
// Example
source = "App/RegisterOTP"
platform = "ios"
limits = {
    "App/RegisterOTP": {
        "per_minute_ios": 10,
        "per_hour_ios": 100,
        "per_minute_web": 5,
        "per_hour_web": 50,
        "per_minute_android": 8,
        "per_hour_android": 80
    }
}
isWithinLimits = validateSourceRateLimit(source, platform, limits)
// isWithinLimits = true if under both per-minute and per-hour limits
```

########## VALIDATION STEP 7: Logging and Sending SMS

After all validations pass:
1. Log the SMS request details
2. Send SMS through the configured provider (PROVIDER_A, PROVIDER_B, or PROVIDER_C)

**Example log entry:**
```json
{
  "source": "App/RegisterOTP",
  "phone_number": "966501234567",
  "headers": {"User-Agent":"Mozilla/5.0..."},
  "content": "Your verification code is 1234",
  "sms_provider": "PROVIDER_A"
}
```

```
// Pseudocode for Validation Step 7
function logAndSendSms(source, mobile, headers, message, provider):
    // Log the SMS request
    log = {
        "source": source,
        "phone_number": mobile,
        "headers": jsonEncode(headers),
        "content": message,
        "sms_provider": provider
    }
    logId = addSmsHistoryToDatabase(log)
    
    // Send SMS based on provider
    if provider == "PROVIDER_A":
        return sendViaProviderA(mobile, message, logId)
    else if provider == "PROVIDER_B":
        return sendViaProviderB(mobile, message, logId)
    else: // Default to PROVIDER_C
        return sendViaProviderC(mobile, message, logId)
        
// Example
source = "App/RegisterOTP"
mobile = "966501234567"
headers = {"User-Agent": "Mozilla/5.0..."}
message = "Your verification code is 1234"
provider = "PROVIDER_A"
success = logAndSendSms(source, mobile, headers, message, provider)
// success = true if SMS was sent successfully
```