import base64
import json
import os
import asyncio
import time
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

async def produce_protected_payload(public_key_b64: str, payload: dict):
    start = time.time()

    # 1. Generate AES-GCM key (256-bit)
    aes_key = os.urandom(32)  # 256 bits

    # 2. Import RSA public key
    rsa_der = base64.b64decode(public_key_b64)
    public_key = serialization.load_der_public_key(rsa_der, backend=default_backend())

    # 3. Wrap AES key with RSA-OAEP (SHA-1)
    wrapped_key = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    # 4. Encrypt payload with AES-GCM
    iv = os.urandom(12)  # 96-bit IV
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    plaintext = json.dumps(payload).encode("utf-8")
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    ciphertext += encryptor.tag  # Append GCM tag at the end

    # 5. Base64 encode outputs
    result = {
        "data": base64.b64encode(wrapped_key).decode(),
        "eventPayload": base64.b64encode(ciphertext).decode(),
        "ivBase64Enc": base64.b64encode(iv).decode(),
        "latency": round((time.time() - start) * 1000, 2)
    }

    return result

async def main(challenge_token, symbolEntry):

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


    f_payload = {
        "symbolEntry": symbolEntry,
        "events": [json.dumps(fingerprint_data)],
        "metrics": []
    }

    result = await produce_protected_payload(challenge_token, f_payload)
    print(json.dumps(result, indent=2))
    return result

async def chef(session, csrf, user_agent, accept_language, cookies, rblx_challenge_id, identifiers, user_id, payloads): # uses curl cffi session
    # user id is the currently authenticated account that you are making changes to
    headers = {
        'User-Agent': user_agent,
        'Accept': '*/*',
        'Accept-Language': accept_language,
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Referer': 'https://www.roblox.com/',
        'Origin': 'https://www.roblox.com',
        'Connection': 'keep-alive',
        'Cookie': cookies,
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-site',
        'Priority': 'u=4',
    }
    response = await session.get(f'https://apis.roblox.com/rotating-client-service/v1/fetch?challengeId={rblx_challenge_id}&identifier={identifiers[0]}', headers=headers)
    data = response.text # base64 encoded javascript challenge
    data = base64.b64decode(response.text).decode()
    payload_token1 = re.search(r'produceProtectedPayload\s*\(\s*"([^"]+)"', data).group(1) # string in the javascript used to generate the protected payload
    print("payload_token1:" + payload_token1)
    solved = await main(payload_token1, payloads[0]) # generate protected payload

    key = solved.get("data")
    iv = solved.get("ivBase64Enc")
    payloadv2 = solved.get("eventPayload")
    # it was so fun the first time lets do it again!
    response = await session.get(f'https://apis.roblox.com/rotating-client-service/v1/fetch?challengeId={rblx_challenge_id}&identifier={identifiers[1]}', headers=headers)
    data = response.text # base64 encoded javascript challenge
    data = base64.b64decode(response.text).decode()
    payload_token2 = re.search(r'produceProtectedPayload\s*\(\s*"([^"]+)"', data).group(1) # string in the javascript used to generate the protected payload, again!
    print("payload_token2:" + payload_token2)
    solved2 = await main(payload_token2, payloads[1]) # generate protected payload

    key2 = solved2.get("data")
    iv2 = solved2.get("ivBase64Enc")
    payloadv22 = solved2.get("eventPayload")
    headers = {
        'User-Agent': user_agent,
        'Accept': '*/*',
        'Accept-Language': accept_language,
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Referer': 'https://www.roblox.com/',
        'Content-Type': 'application/json-patch+json',
        'x-csrf-token': csrf,
        'Origin': 'https://www.roblox.com',
        'Connection': 'keep-alive',
        'Cookie': cookies,
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-site',
        'Priority': 'u=4',
        'TE': 'trailers',
    }
    payload = {
        "userId": str(user_id),
        "challengeId": rblx_challenge_id,
        "payload": payloads[0], # in challenge metadata expectedSymbols, 0th index is for first submit request 1st index for 2nd submit request
        "payloadV2": payloadv2,  # solved in chef js challenge
        "params": { # solved in chef js challenge all below
            "key": key,
            "iv": iv
        }
    }
    print(payload)
    response = await session.post('https://apis.roblox.com/rotating-client-service/v1/submit', headers=headers, json=payload)

    headers = {
        'User-Agent': user_agent,
        'Accept': '*/*',
        'Accept-Language': accept_language,
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Referer': 'https://www.roblox.com/',
        'Content-Type': 'application/json-patch+json',
        'x-csrf-token': csrf,
        'Origin': 'https://www.roblox.com',
        'Connection': 'keep-alive',
        'Cookie': cookies,
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-site',
        'Priority': 'u=4',
        'TE': 'trailers',
    }

    payload = {
        "userId": str(user_id),
        "challengeId": rblx_challenge_id,
        "payload": payloads[1], # in challenge metadata expectedSymbols, 0th index is for first submit request 1st index for 2nd submit request
        "payloadV2": payloadv22,  # solved in chef js challenge
        "params": { # solved in chef js challenge all below
            "key": key2,
            "iv": iv2
        }
    }
    print(payload)

    response = await session.post('https://apis.roblox.com/rotating-client-service/v1/submit', headers=headers, json=payload)