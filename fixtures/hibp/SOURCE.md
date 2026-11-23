# hibp fixtures

- `breaches.json`: 8 real entries from `https://haveibeenpwned.com/api/v3/breaches`, fetched 23 Nov 2026 (sandbox
  clock): `Adobe`, `Bromcom`, `AllegedATT`, `AdultFriendFinder`, `Acuity`, `JustDate`, `126`, `AlienStealerLogs`.
  `Description` cut to 200 characters; nothing else changed.
- `latestbreach.json`: the real `/api/v3/latestbreach` response of the same day, `Description` cut to 200 characters.
- `bad.json`, `extra-key.json`: hand-written variants of the Adobe and Bromcom entries (no `Name`; extra `IsNewFlag`).
- Licence: CC BY 4.0, credit "Have I Been Pwned (haveibeenpwned.com)".
