ALTER TABLE %TABLE_PREFIX%link_status_reports CHANGE lsr_url lsr_url VARCHAR(1024) CHARSET utf8 COLLATE utf8_general_ci NOT NULL, DROP PRIMARY KEY, ADD PRIMARY KEY (lsr_url(255)), ADD UNIQUE INDEX idx_lsr_url (lsr_url(255));