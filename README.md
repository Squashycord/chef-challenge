Roblox's chef JS challenge is a challenge deployed when making 2FA changes to a roblox account, used for anti-bot and browser fingerprinting.

## GETTING CHALLENGE INFORMATION

```
rblx_challenge_id = response.headers["rblx-challenge-id"]
challenge_metadata = json.loads(base64.b64decode(response.headers["rblx-challenge-metadata"]).decode('utf-8'))
identifiers = challenge_metadata.get("scriptIdentifiers", [])
payloads = challenge_metadata.get("expectedSymbols", [])
```
Roblox challenge ID: In the request that roblox serves the base64 encoded JS challenge, roblox returns the header "rblx-challenge-id".

identifiers: In the request that roblox serves the base64 encoded JS challenge, roblox returns the base64 encoded header "rblx-challenge-metadata". After decoding the value, the identifiers are in the "scriptIdentifiers" key in the json object.

payloads (expectedSymbols): In the request that roblox serves the base64 encoded JS challenge, roblox returns the base64 encoded header "rblx-challenge-metadata". After decoding the value, the identifiers are in the "expectedSymbols" key in the json object.
