-- home-latest: newest signal per kind for the home page; covers vuln_key so counts read the index only.
CREATE INDEX signals_by_kind_seen ON signals (kind, first_seen DESC, vuln_key);
