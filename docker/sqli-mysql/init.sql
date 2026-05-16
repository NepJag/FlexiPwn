CREATE USER 'webapp'@'localhost' IDENTIFIED WITH mysql_native_password BY 'webapp123';
GRANT ALL ON webapp.* TO 'webapp'@'localhost';

CREATE DATABASE IF NOT EXISTS webapp;
USE webapp;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(50) NOT NULL,
    role VARCHAR(20) DEFAULT 'user'
);

CREATE TABLE sensitive_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    secret_key VARCHAR(100) NOT NULL,
    owner VARCHAR(50) NOT NULL
);

INSERT INTO users VALUES (1, 'admin', 'admin123', 'admin');
INSERT INTO users VALUES (2, 'student', 'student123', 'user');

INSERT INTO sensitive_data VALUES (1, 'FLAG{sql_injection_detected}', 'admin');
INSERT INTO sensitive_data VALUES (2, 'internal-api-key-xyz', 'system');
