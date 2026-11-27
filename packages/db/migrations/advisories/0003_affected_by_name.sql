-- The "is this a package MTI has records for" check on the watch route is one seek on (name, ecosystem).
CREATE INDEX affected_by_name ON affected (name, ecosystem);
