Roblox's chef JS challenge is a challenge deployed when making 2FA changes to a roblox account, used for anti-bot and browser fingerprinting.

## Getting challenge information
```
rblx_challenge_id = response.headers["rblx-challenge-id"]
challenge_metadata = json.loads(base64.b64decode(response.headers["rblx-challenge-metadata"]).decode('utf-8'))
identifiers = challenge_metadata.get("scriptIdentifiers", [])
payloads = challenge_metadata.get("expectedSymbols", [])
```
Roblox challenge ID: In the request that roblox initializes the chef challenge, roblox returns the header "rblx-challenge-id".

identifiers: In the request that roblox initializes the chef challenge, roblox returns the base64 encoded header "rblx-challenge-metadata". After decoding the value, the identifiers are in the "scriptIdentifiers" key in the json object.

payloads (expectedSymbols): In the request that roblox initializes the chef challenge, roblox returns the base64 encoded header "rblx-challenge-metadata". After decoding the value, the identifiers are in the "expectedSymbols" key in the json object.

challenge_token: In the challenge JS, (https://apis.roblox.com/rotating-client-service/v1/fetch? ..) it runs a produceProtectedPayload() function with the challenge_token as a paramater and totalPayloadToEncrypt as the second paramater. The regex to find the challenge token below.
```
re.search(r'produceProtectedPayload\s*\(\s*"([^"]+)"', data).group(1)
```
Challenge JS code where challenge_token is found:
```
const protectedPayload = await ChefScript?.protect?.produceProtectedPayload("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDtYgpV9pTehPhh1VB80VvJeLrlvF4Gpi2hXgcvE/cTALPk0ZqFLcwN42B3HWWFfLnC8lO94Bhna3Ph4p7gzqMAtkJ0tj/j2TAlL7I8M9o39xGqNjMjm9A3A5O5mHl+ETLdRYAzc7OsMFVo0VlUxxaMnQMEhTU1tV1zdXGxQ9/cEwIDAQAB", totalPayloadToEncrypt);
```

## Generate protected payload

Generate payload to protect:
```
f_payload = {
    "symbolEntry": symbolEntry, # payloads (expectedSymbols), found above
    "events": [json.dumps(fingerprint_data)], # fingerprint in chef.py
    "metrics": [] # hardcoded
}
```
## Payload Protection

This function protects the challenge payload using **hybrid encryption**:

1. **Generate a random AES-256 key** (used for the actual payload encryption).
2. **Encrypt the AES key** using the base64 decoded challenge_token (found above), as a key using **RSA-OAEP + SHA-1**.
3. **Encrypt the payload** with **AES-256-GCM**.
4. **Bundle the results**:
   - `data` → Base64 RSA-encrypted AES key
   - `eventPayload` → Base64 AES-GCM encrypted payload + authentication tag
   - `ivBase64Enc` → Base64 initialization vector
5. Return the packaged data along with the time taken (`latency`). code: round((time.time() - start) * 1000, 2)
```
result = {
    "data": base64.b64encode(wrapped_key).decode(),
    "eventPayload": base64.b64encode(ciphertext).decode(),
    "ivBase64Enc": base64.b64encode(iv).decode(),
    "latency": round((time.time() - start) * 1000, 2)
}
```
All of the payload protection code can be found in the produce_protected_payload() function in chef.py

## Fingerprints
Fingerprints aren't dynamic or validated. 
The fingerprint is sent to the /submit api in a protected payload (read more above)

Example fingerprint:
```
    fingerprint_data = { # example fingerprint, can have the EXACT same fingerprint every request, roblox doesn't validate / ratelimit
        "symbolEntry": symbolEntry,
        "events": [
            {
                "audio": {
                    "sampleHash": 1168.9068228197468,
                    "oscillator": "sine",
                    "maxChannels": 1,
                    "channelCountMode": "max"
                },
                "canvas": {
                    "commonImageDataHash": "6999abd310347a74500b74b30bb97077"
                },
                "fonts": {
                    "Arial Black": 531.9140625,
                    "Calibri": 420.046875,
                    "Candara": 435.4453125,
                    "Comic Sans MS": 462.4453125,
                    "Constantia": 469.86328125,
                    "Courier": 432.0703125,
                    "Courier New": 432.0703125,
                    "Franklin Gothic Medium": 431.82421875,
                    "Georgia": 475.2421875,
                    "Impact": 395.54296875,
                    "Lucida Console": 433.828125,
                    "Lucida Sans Unicode": 472.0078125,
                    "Segoe Print": 514.30078125,
                    "Segoe Script": 525.234375,
                    "Segoe UI": 450,
                    "Tahoma": 432.45703125,
                    "Trebuchet MS": 428.90625,
                    "Verdana": 486.5625
                },
                "hardware": {
                    "videocard": {
                        "vendor": "WebKit",
                        "renderer": "WebKit WebGL",
                        "version": "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
                        "shadingLanguageVersion": "WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)"
                    },
                    "architecture": 255,
                    "deviceMemory": "8",
                    "jsHeapSizeLimit": 4294705152
                },
                "locales": {
                    "languages": "en-US",
                    "timezone": "America/Chicago"
                },
                "permissions": {
                    "accelerometer": "granted",
                    "backgroundFetch": "granted",
                    "backgroundSync": "granted",
                    "camera": "prompt",
                    "clipboardRead": "prompt",
                    "clipboardWrite": "granted",
                    "displayCapture": "prompt",
                    "gyroscope": "granted",
                    "geolocation": "prompt",
                    "localFonts": "prompt",
                    "magnetometer": "granted",
                    "microphone": "prompt",
                    "midi": "prompt",
                    "notifications": "prompt",
                    "paymentHandler": "granted",
                    "persistentStorage": "prompt",
                    "storageAccess": "granted",
                    "windowManagement": "prompt"
                },
                "plugins": {
                    "plugins": [
                        "PDF Viewer|internal-pdf-viewer|Portable Document Format",
                        "Chrome PDF Viewer|internal-pdf-viewer|Portable Document Format",
                        "Chromium PDF Viewer|internal-pdf-viewer|Portable Document Format",
                        "Microsoft Edge PDF Viewer|internal-pdf-viewer|Portable Document Format",
                        "WebKit built-in PDF|internal-pdf-viewer|Portable Document Format"
                    ]
                },
                "screen": {
                    "is_touchscreen": False,
                    "maxTouchPoints": 0,
                    "colorDepth": 24,
                    "mediaMatches": [
                        "prefers-contrast: no-preference",
                        "any-hover: hover",
                        "any-pointer: fine",
                        "pointer: fine",
                        "hover: hover",
                        "update: fast",
                        "prefers-reduced-motion: no-preference",
                        "prefers-reduced-transparency: no-preference",
                        "scripting: enabled",
                        "forced-colors: none"
                    ]
                },
                "system": {
                    "platform": "Win32",
                    "cookieEnabled": True,
                    "productSub": "20030107",
                    "product": "Gecko",
                    "useragent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
                    "hardwareConcurrency": 12,
                    "browser": {
                        "name": "Chrome",
                        "version": "138.0"
                    },
                    "applePayVersion": 0
                },
                "webgl": {
                    "commonImageHash": "3a4ed1c6378f68583893dd719f84f6c9"
                },
                "math": {
                    "acos": 1.0471975511965979,
                    "asin": -9.614302481290016e-17,
                    "atan": 4.578239276804769e-17,
                    "cos": -4.854249971455313e-16,
                    "cosh": 1.9468519159297506,
                    "e": 2.718281828459045,
                    "largeCos": 0.7639704044417283,
                    "largeSin": -0.6452512852657808,
                    "largeTan": -0.8446024630198843,
                    "log": 6.907755278982137,
                    "pi": 3.141592653589793,
                    "sin": -1.9461946644816207e-16,
                    "sinh": -0.6288121810679035,
                    "sqrt": 1.4142135623730951,
                    "tan": 6.980860926542689e-14,
                    "tanh": -0.39008295789884684
                },
                "data_latency_ms": 156.89999999850988
            }
        ],
        "metrics": []
    }
```
