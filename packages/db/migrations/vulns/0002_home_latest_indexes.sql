-- home-latest: newest published for the home page. Partial indexes, one per kind of record, so each
-- LIMIT 10 query and each count reads the index only (the WHERE text must match the query's).
CREATE INDEX vulns_published_vuln ON vulns (published) WHERE hot = 1 AND substr(key, 1, 4) != 'MAL-';
CREATE INDEX vulns_published_mal ON vulns (published) WHERE hot = 1 AND substr(key, 1, 4) = 'MAL-';
