/* Unique key is used to trigger update of existing rows rather than allow duplicate entries */
CREATE TABLE IF NOT EXISTS `results` (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    hostmsb BIGINT UNSIGNED DEFAULT 0,
    hostlsb BIGINT UNSIGNED DEFAULT 0,
    createdate BIGINT UNSIGNED DEFAULT 0,
    session BIGINT UNSIGNED DEFAULT 0,
    portnum BIGINT UNSIGNED DEFAULT 0,
    portresult BIGINT UNSIGNED DEFAULT 0,
/* 46 = INET6_ADDRSTRLEN + 1 */
    indirecthost VARCHAR(46) DEFAULT '',
    ts TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    INDEX idx_ts (ts),
    UNIQUE KEY idx_scan_identity
        (hostmsb, hostlsb, createdate, session, portnum)
) ENGINE=InnoDB;
