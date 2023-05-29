CREATE TABLE `user_account` (
  `id` BINARY(16) NOT NULL,
  `username` varchar(100) NOT NULL,
  `password` varchar(100) NOT NULL,
  `name` varchar(100) NOT NULL,
  `enabled` tinyint(1) NOT NULL,
  `account_non_expired` tinyint(1) NOT NULL,
  `credentials_non_expired` tinyint(1) NOT NULL,
  `account_non_locked` tinyint(1) NOT NULL,
  `provider` varchar(15) NOT NULL DEFAULT 'LOCAL',
  PRIMARY KEY (`id`),
  UNIQUE KEY(username)
);

CREATE TABLE `role` (
  `id` TINYINT(1) unsigned NOT NULL AUTO_INCREMENT,
  `rolename` varchar(60) NOT NULL DEFAULT '',
  `description` varchar(255) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY(rolename)
);

CREATE TABLE `user_account_role` (
  `user_id` BINARY(16) NOT NULL,
  `role_id` TINYINT(1) unsigned NOT NULL,
  KEY `pk_user` (`user_id`),
  KEY `pk_role` (`role_id`),
  CONSTRAINT `pk_role` FOREIGN KEY (`role_id`) REFERENCES `role` (`id`),
  CONSTRAINT `pk_user` FOREIGN KEY (`user_id`) REFERENCES `user_account` (`id`)
);

insert into role(rolename,description) values('ROLE_ADMIN', 'Admin Role');
insert into role(rolename,description) values('ROLE_USER', 'User Role');

insert into user_account(id, username, password, name, enabled, account_non_expired, credentials_non_expired, account_non_locked)
values(UNHEX('f62e3850c7f044a6b6eade1fbf15f46f'), 'admin@secdevoops.es', '$2a$10$a8vUqzVb.MC23cfrnLPfQ.3WDlRZL9O9nATkjrc7JN4WipKHLAsJu', 'Admin', true, true, true, true);

insert into user_account_role(user_id, role_id) values(UNHEX('f62e3850c7f044a6b6eade1fbf15f46f'), 1);

