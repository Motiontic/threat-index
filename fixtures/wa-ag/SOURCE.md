# wa-ag fixtures

- `sb4j-ca4h.sample.json`: `https://data.wa.gov/resource/sb4j-ca4h.json?$order=datesubmitted%20DESC,id%20DESC&$limit=5`,
  fetched 23 Nov 2026 with `ThreatIndex-test/0.1 (+https://github.com/Motiontic/threat-index)` (HTTP 200). The first 3
  rows are real, as served (ids 26286, 26285, 26284). The last 4 are **hand-written**: only a range and no count,
  `"1,200"` with an invalid leap day, an unknown key, and `id` `"abc"`.
- The dataset's 25 columns (from `https://data.wa.gov/api/views/sb4j-ca4h.json`): `dateaware`, `datesubmitted`,
  `databreachcause`, `datestart`, `dateend`, `name`, `id`, `cyberattacktype`, `washingtoniansaffected`, `industrytype`,
  `businesstype`, `year`, `yeartext`, `washingtoniansaffectedrange`, `breachlifecyclerange`, `daystocontainbreach`,
  `daystoidentifybreach`, `daysbreachlifecycle`, `discoveredinprogress`, `daysofexposure`,
  `dayselapsedbetweenendanddiscovery`, `endedondaydiscovered`, `dayselapsedbeforenotification`,
  `daysofexposurerange`, `entitystate`.
- Licence: no stated licence on the dataset; source marked `ask`.
