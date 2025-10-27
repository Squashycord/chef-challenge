from curl_cffi import AsyncSession
import asyncio
import html
import re
import json
import base64
import time
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import os
# to authenticate your Roblox account
roblo_security = input("What is the roblosecurity cookie for the account you would like to test the chef challenge with?\n")

accept_language = 'en-US,en;q=0.5'

cookies = f".ROBLOSECURITY={roblo_security};"

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
    return result

async def chef(session, csrf, user_agent, accept_language, cookies, rblx_challenge_id, identifiers, user_id, btid): # uses curl cffi session
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

    expectedSymbol1 = re.search(r'expectedSymbol="([^"]+)"', data).group(1) # roblox changed where the expectedSymbol is found when they updated, this is the updated location
    solved = await main(payload_token1, expectedSymbol1) # generate protected payload

    key = solved.get("data")
    iv = solved.get("ivBase64Enc")
    payloadv2 = solved.get("eventPayload")
    # it was so fun the first time lets do it again!
    response = await session.get(f'https://apis.roblox.com/rotating-client-service/v1/fetch?challengeId={rblx_challenge_id}&identifier={identifiers[1]}', headers=headers)
    data = response.text # base64 encoded javascript challenge
    data = base64.b64decode(response.text).decode()
    payload_token2 = re.search(r'produceProtectedPayload\s*\(\s*"([^"]+)"', data).group(1) # string in the javascript used to generate the protected payload, again!

    expectedSymbol2 = re.search(r'expectedSymbol="([^"]+)"', data).group(1) # roblox changed where the expectedSymbol is found when they updated, this is the updated location

    solved2 = await main(payload_token2, expectedSymbol2) # generate protected payload

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
        #"payload": payloads[0], # (outdated) -> in challenge metadata expectedSymbols, 0th index is for first submit request 1st index for 2nd submit request <---- ALL OF THIS INFORMATION IS OUTDATED, "payload" is no longer sent in this request
        "payloadV2": payloadv2,  # solved in chef js challenge
        "params": { # solved in chef js challenge all below
            "key": key,
            "iv": iv
        },
        "btid": str(btid)  # time when the RBXEventTrackerV2 cookie was given from roblox, in unix microseconds
    }
    response = await session.post('https://apis.roblox.com/rotating-client-service/v1/submit', headers=headers, json=payload)
    print(f"Solved first part of chef challenge|ExpectedSymbol = {expectedSymbol1}|PayloadToken = {payload_token1}\n")
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
        #"payload": payloads[1], # (outdated) in challenge metadata expectedSymbols, 0th index is for first submit request 1st index for 2nd submit request <---- ALL OF THIS INFORMATION IS OUTDATED, "payload" is no longer sent in this request 
        "payloadV2": payloadv22,  # solved in chef js challenge
        "params": { # solved in chef js challenge all below
            "key": key2,
            "iv": iv2
        },
        "btid": str(btid)  # time when the RBXEventTrackerV2 cookie was given from roblox, in unix microseconds
    }

    response = await session.post('https://apis.roblox.com/rotating-client-service/v1/submit', headers=headers, json=payload)
    print(f"Solved second part of chef challenge|ExpectedSymbol = {expectedSymbol2}|PayloadToken = {payload_token2}\n")


async def get_session(proxy):
    session = AsyncSession(
        impersonate="chrome136",
        default_headers=False,
        ja3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17613-65037-65281,4588-29-23-24,0",
        akamai="1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
        extra_fp={
            "tls_signature_algorithms": [
                "ecdsa_secp256r1_sha256",
                "rsa_pss_rsae_sha256",
                "rsa_pkcs1_sha256",
                "ecdsa_secp384r1_sha384",
                "rsa_pss_rsae_sha384",
                "rsa_pkcs1_sha384",
                "rsa_pss_rsae_sha512",
                "rsa_pkcs1_sha512"
            ],
            "tls_grease": True,
            "tls_permute_extensions": True
        },
        verify=False,
        http_version=3
    )

    session.proxies = {
        "https": proxy
    }

    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
    return session, user_agent

async def add_authenticator(): # requests a code in order to add an authenticator, for chef example
    session, user_agent = await get_session(None)

    headers = {
        'User-Agent': user_agent,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Referer': 'https://www.roblox.com/home',
        'Sec-GPC': '1',
        'Connection': 'keep-alive',
        'Cookie': cookies,
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'Priority': 'u=0, i',
        'TE': 'trailers',
    }
    import time

    btid = str(int(time.time() * 1_000_000)) # time when the RBXEventTrackerV2 cookie was given from roblox, its given in the my/account request below

    response = await session.get('https://www.roblox.com/my/account#!/security', headers=headers) # get x-csrf-token

    user_id = re.search(r'data-userid="(\d+)"', response.text).group(1)

    csrf = html.unescape(re.search(r'<meta\s+name=["\']csrf-token["\']\s+data-token=["\']([^"\']+)["\']', response.text).group(1))

    headers = {
        'User-Agent': user_agent,
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Content-Type': 'application/json;charset=utf-8',
        'x-bound-auth-token': 'v1|RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=|1761579335|7tTAmAaDn5GflxeT6EcD1CTA5/6t2YCBzs41J86sbyWXXeeN5eK8indBIA/OkjEQPkqdbNry6Ev1mXwkJ5HXoA==|AFEYdh2kw46BD8UtHxEph3b4RWmVuMCVEoqZxTHtMqbqfL81TSPii7+RyMBICz8hnLCjSKVVixfv8NeCz5fxsw==',
        'x-csrf-token': csrf,
        'Origin': 'https://www.roblox.com',
        'Sec-GPC': '1',
        'Connection': 'keep-alive',
        'Referer': 'https://www.roblox.com/',
        'Cookie': cookies,
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-site',
        'TE': 'trailers',
    }

    payload = {}

    response = await session.post(f'https://twostepverification.roblox.com/v1/users/{user_id}/configuration/authenticator/enable', headers=headers, json=payload)

    if "Challenge is required to authorize the request" in response.text and response.headers['rblx-challenge-type'] == "chef":
        print("\nReceived chef challenge! Solving...\n")

        rblx_challenge_id = response.headers["rblx-challenge-id"]
        challenge_metadata = json.loads(base64.b64decode(response.headers["rblx-challenge-metadata"]).decode('utf-8'))
        identifiers = challenge_metadata.get("scriptIdentifiers", [])
        # payloads = challenge_metadata.get("expectedSymbols", []) # outdated

        await chef(session, csrf, user_agent, accept_language, cookies, rblx_challenge_id, identifiers, user_id, btid) # solve the chef challenge

        headers = {
            'User-Agent': user_agent,
            'Accept': '*/*',
            'Accept-Language': accept_language,
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Referer': 'https://www.roblox.com/',
            'Content-Type': 'application/json',
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
        challenge_metadata = {
            "userId": str(user_id),
            "challengeId": rblx_challenge_id
        }
        payload = {
            'challengeID': rblx_challenge_id,
            'challengeMetadata': json.dumps(challenge_metadata),
            'challengeType': 'chef',
        }
        response = await session.post('https://apis.roblox.com/challenge/v1/continue', headers=headers, json=payload)
        if response.json()['challengeId']:
            print("Successfully solved the chef challenge! A 2-Step Verification email should have been sent to your roblox email.")
        else:
            print("Something went wrong while sending the 2-Step Verification email.")
    elif "Challenge is required to authorize the request" in response.text and response.headers['rblx-challenge-type'] == "blocksession":
        print("Roblox blocked this settings change attempt, check your email to allow this and try again.")
    elif "Too many requests" in response.text:
        print("Roblox ratelimited you from settings changes! Wait a little bit before trying again or use a different account.")
    else:
        print(response.text)
        print(response.headers)
        print("\n")
        print("Couldn't get chef challenge :(")


asyncio.run(add_authenticator())
