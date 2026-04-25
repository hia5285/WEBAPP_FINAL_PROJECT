-- ===========================================================================
-- CSecFiles -- Database Schema and Seed Data
-- ===========================================================================
-- Target: MariaDB / MySQL via XAMPP phpMyAdmin
-- Usage : Open phpMyAdmin, click "Import", choose this file, then Go.
--         Or run from CLI: mysql -u root < database/csecfiles.sql
--
-- Note on passwords:
--   The seeded users below have PLAINTEXT passwords. This is acceptable only
--   because the VULNERABLE version of CSecFiles is meant to be insecure and
--   the HARDENED version's login.php detects a non-bcrypt value, verifies it
--   in plaintext, and silently upgrades the row to a real password_hash on
--   the first successful login. New accounts created via hardened/register.php
--   are stored as proper bcrypt hashes from the start.
-- ===========================================================================

CREATE DATABASE IF NOT EXISTS `csecfiles`
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE `csecfiles`;

-- ---------------------------------------------------------------------------
-- Drop existing tables so the script is idempotent.
-- ---------------------------------------------------------------------------
DROP TABLE IF EXISTS `activity_logs`;
DROP TABLE IF EXISTS `comments`;
DROP TABLE IF EXISTS `documents`;
DROP TABLE IF EXISTS `users`;

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------
CREATE TABLE `users` (
    `id`                       INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `full_name`                VARCHAR(150)  NOT NULL,
    `email`                    VARCHAR(190)  NOT NULL,
    `username`                 VARCHAR(60)   NOT NULL,
    `password`                 VARCHAR(255)  NOT NULL,
    `role`                     ENUM('admin','manager','employee') NOT NULL DEFAULT 'employee',
    `department`               VARCHAR(80)   NOT NULL DEFAULT 'General',
    `failed_login_attempts`    INT UNSIGNED  NOT NULL DEFAULT 0,
    `last_failed_login`        DATETIME      NULL DEFAULT NULL,
    `locked_until`             DATETIME      NULL DEFAULT NULL,
    `created_at`               DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uniq_username` (`username`),
    UNIQUE KEY `uniq_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- documents
-- ---------------------------------------------------------------------------
CREATE TABLE `documents` (
    `id`           INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `title`        VARCHAR(200)  NOT NULL,
    `description`  TEXT          NULL,
    `file_name`    VARCHAR(255)  NOT NULL,
    `file_path`    VARCHAR(500)  NOT NULL,
    `owner_id`     INT UNSIGNED  NOT NULL,
    `department`   VARCHAR(80)   NOT NULL DEFAULT 'General',
    `visibility`   ENUM('private','department','public') NOT NULL DEFAULT 'private',
    `created_at`   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_owner` (`owner_id`),
    KEY `idx_department` (`department`),
    CONSTRAINT `fk_documents_owner`
        FOREIGN KEY (`owner_id`) REFERENCES `users`(`id`)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- comments
-- ---------------------------------------------------------------------------
CREATE TABLE `comments` (
    `id`           INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `document_id`  INT UNSIGNED NOT NULL,
    `user_id`      INT UNSIGNED NOT NULL,
    `comment`      TEXT NOT NULL,
    `created_at`   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_document` (`document_id`),
    KEY `idx_user` (`user_id`),
    CONSTRAINT `fk_comments_document`
        FOREIGN KEY (`document_id`) REFERENCES `documents`(`id`)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT `fk_comments_user`
        FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- activity_logs
-- ---------------------------------------------------------------------------
CREATE TABLE `activity_logs` (
    `id`         INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`    INT UNSIGNED NULL,
    `action`     VARCHAR(80)  NOT NULL,
    `details`    VARCHAR(500) NULL,
    `created_at` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_user` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===========================================================================
-- Seed data
-- ===========================================================================

INSERT INTO `users`
    (`id`, `full_name`,        `email`,                  `username`, `password`,     `role`,     `department`)
VALUES
    (1, 'Site Administrator', 'admin@csecfiles.local',   'admin',    'admin123',     'admin',    'IT'),
    (2, 'John Doe',            'john@csecfiles.local',   'john',     'password123',  'employee', 'Engineering'),
    (3, 'Sara Khan',           'sara@csecfiles.local',   'sara',     'password123',  'employee', 'Marketing'),
    (4, 'Alex Manager',        'manager@csecfiles.local','manager',  'manager123',   'manager',  'Engineering');

INSERT INTO `documents`
    (`id`, `title`,                              `description`,                                                          `file_name`,                  `file_path`,                          `owner_id`, `department`,  `visibility`)
VALUES
    (1, 'Company Policy 2026',                   'Official corporate policy for the year. Open to everyone.',            'company_policy_2026.txt',    'uploads/company_policy_2026.txt',    1, 'IT',          'public'),
    (2, 'Q1 Engineering Roadmap',                'Internal Engineering planning document for Q1.',                       'q1_engineering_roadmap.txt', 'uploads/q1_engineering_roadmap.txt', 2, 'Engineering', 'department'),
    (3, 'John Performance Review',               'Confidential annual review notes -- private to John.',                 'john_review.txt',            'uploads/john_review.txt',            2, 'Engineering', 'private'),
    (4, 'Marketing Campaign Brief',              'Spring campaign brief, shared with the Marketing team.',               'marketing_brief.txt',        'uploads/marketing_brief.txt',        3, 'Marketing',   'department'),
    (5, 'Sara Salary Negotiation Notes',         'Confidential personal notes -- private to Sara.',                      'sara_salary_notes.txt',      'uploads/sara_salary_notes.txt',      3, 'Marketing',   'private'),
    (6, 'Manager Strategy Memo',                 'Restricted strategy memo for the Engineering manager only.',           'manager_memo.txt',           'uploads/manager_memo.txt',           4, 'Engineering', 'private');

INSERT INTO `comments`
    (`document_id`, `user_id`, `comment`)
VALUES
    (1, 1, 'Welcome to CSecFiles. Please read the policy carefully.'),
    (2, 2, 'Roadmap reviewed. Targets look reasonable for Q1.'),
    (4, 3, 'Looking forward to feedback from the team.'),
    (1, 4, 'Acknowledged on behalf of Engineering management.');

INSERT INTO `activity_logs`
    (`user_id`, `action`,         `details`)
VALUES
    (1, 'seed', 'Initial database seed loaded.'),
    (2, 'seed', 'Engineering employee account created.'),
    (3, 'seed', 'Marketing employee account created.'),
    (4, 'seed', 'Engineering manager account created.');
