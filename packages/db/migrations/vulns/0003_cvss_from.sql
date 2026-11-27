-- cvss_from: the MTI source whose record delivered the CVSS score (cvss_source is only the scorer's name).
-- No backfill: readers treat NULL as 'nvd' when cvss_source = 'nvd', else 'cve-list' (see @ti/core/cvss).
ALTER TABLE vulns ADD COLUMN cvss_from TEXT;
