-- breach-linking: the normalised filer name, so a notice can be matched to earlier notices by name.
ALTER TABLE breach_notices ADD COLUMN name_key TEXT;
CREATE INDEX notices_by_name ON breach_notices (name_key);
