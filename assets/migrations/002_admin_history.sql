CREATE INDEX history_order ON history(occurred_at, id);
CREATE INDEX history_application_order ON history(application, occurred_at, id);
CREATE INDEX history_subject_order ON history(application, subject, occurred_at, id);
CREATE INDEX history_credential_order ON history(credential, occurred_at, id);
