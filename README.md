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
