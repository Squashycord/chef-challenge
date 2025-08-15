Roblox's chef JS challenge is a challenge deployed when making 2FA changes to a roblox account, used for anti-bot and browser fingerprinting.

## GETTING CHALLENGE INFORMATION

Roblox challenge ID: In the request that roblox serves the base64 encoded JS challenge, roblox returns the header "rblx-challenge-id".

identifiers: In the request that roblox serves the base64 encoded JS challenge, roblox returns the base64 encoded header "rblx-challenge-metadata". After decoding the value, the identifiers are in the "scriptIdentifiers" key in the json object.

payloads (expectedSymbols): In the request that roblox serves the base64 encoded JS challenge, roblox returns the base64 encoded header "rblx-challenge-metadata". After decoding the value, the identifiers are in the "expectedSymbols" key in the json object.
