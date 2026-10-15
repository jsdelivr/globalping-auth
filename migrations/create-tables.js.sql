CREATE TABLE IF NOT EXISTS `directus_users` (
	`id` CHAR(36) PRIMARY KEY,
	`github_username` VARCHAR(255),
	`selected_orgs` LONGTEXT NOT NULL DEFAULT '[]' CHECK (json_valid(`selected_orgs`))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `gp_orgs` (
	`id` CHAR(36) PRIMARY KEY,
	`name` VARCHAR(255) NOT NULL,
	`github_id` VARCHAR(255) NOT NULL,
	`adoption_token` VARCHAR(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `gp_accounts` (
	`id` CHAR(36) PRIMARY KEY,
	`user` CHAR(36),
	`org` CHAR(36),
	CONSTRAINT `gp_accounts_user_unique` UNIQUE (`user`),
	CONSTRAINT `gp_accounts_org_unique` UNIQUE (`org`),
	CONSTRAINT `gp_accounts_user_xor_org` CHECK (`user` IS NULL <> (`org` IS NULL)),
	CONSTRAINT `gp_accounts_user_foreign` FOREIGN KEY (`user`) REFERENCES `directus_users` (`id`) ON DELETE CASCADE,
	CONSTRAINT `gp_accounts_org_foreign` FOREIGN KEY (`org`) REFERENCES `gp_orgs` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `gp_org_members` (
	`id` CHAR(36) PRIMARY KEY,
	`org` CHAR(36) NOT NULL,
	`user` CHAR(36) NOT NULL,
	`role` VARCHAR(255) NOT NULL,
	CONSTRAINT `gp_org_members_org_user_unique` UNIQUE (`org`, `user`),
	CONSTRAINT `gp_org_members_org_foreign` FOREIGN KEY (`org`) REFERENCES `gp_orgs` (`id`) ON DELETE CASCADE,
	CONSTRAINT `gp_org_members_user_foreign` FOREIGN KEY (`user`) REFERENCES `directus_users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `gp_apps` (
	`id` char(36) NOT NULL,
	`user_created` char(36) DEFAULT NULL,
	`date_created` timestamp NULL DEFAULT NULL,
	`user_updated` char(36) DEFAULT NULL,
	`date_updated` timestamp NULL DEFAULT NULL,
	`name` varchar(255) NOT NULL,
	`owner_name` varchar(255) NULL DEFAULT NULL,
	`owner_url` varchar(255) NULL DEFAULT NULL,
	`secrets` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT '\'[]\'' NOT NULL CHECK (json_valid(`secrets`)),
	`redirect_urls` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`redirect_urls`)),
	`grants` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT '\'[]\'' CHECK (json_valid(`grants`)),
	`access_token_lifetime` int(11) DEFAULT NULL,
	`refresh_token_lifetime` int(11) DEFAULT NULL,
	PRIMARY KEY (`id`),
	KEY `gp_apps_user_created_foreign` (`user_created`),
	KEY `gp_apps_user_updated_foreign` (`user_updated`),
	CONSTRAINT `gp_apps_user_created_foreign` FOREIGN KEY (`user_created`) REFERENCES `directus_users` (`id`),
	CONSTRAINT `gp_apps_user_updated_foreign` FOREIGN KEY (`user_updated`) REFERENCES `directus_users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `gp_tokens` (
	`date_created` timestamp NULL DEFAULT NULL,
	`date_last_used` date DEFAULT NULL,
	`date_updated` timestamp NULL DEFAULT NULL,
	`expire` date DEFAULT NULL,
	`id` int(10) unsigned NOT NULL AUTO_INCREMENT,
	`name` varchar(255) NOT NULL,
	`origins` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT '[]' CHECK (json_valid(`origins`)),
	`user_created` char(36) DEFAULT NULL,
	`user_updated` char(36) DEFAULT NULL,
	`account_id` varchar(36) DEFAULT NULL,
	`value` varchar(255) DEFAULT NULL,
	`app_id` char(36) DEFAULT NULL,
	`scopes` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT '[]' CHECK (json_valid(`scopes`)),
	`type` varchar(255) NOT NULL DEFAULT 'access_token',
	`parent` int(10) unsigned DEFAULT NULL,
	PRIMARY KEY (`id`),
	UNIQUE KEY `gp_tokens_value_unique` (`value`),
	KEY `gp_tokens_user_created_foreign` (`user_created`),
	KEY `gp_tokens_user_updated_foreign` (`user_updated`),
	KEY `value_index` (`value`),
	KEY `gp_tokens_app_id_foreign` (`app_id`),
	KEY `gp_tokens_parent_foreign` (`parent`),
	CONSTRAINT `gp_tokens_account_id_foreign` FOREIGN KEY (`account_id`) REFERENCES `gp_accounts` (`id`) ON DELETE CASCADE,
	CONSTRAINT `gp_tokens_app_id_foreign` FOREIGN KEY (`app_id`) REFERENCES `gp_apps` (`id`) ON DELETE CASCADE,
	CONSTRAINT `gp_tokens_parent_foreign` FOREIGN KEY (`parent`) REFERENCES `gp_tokens` (`id`) ON DELETE CASCADE,
	CONSTRAINT `gp_tokens_user_created_foreign` FOREIGN KEY (`user_created`) REFERENCES `directus_users` (`id`) ON DELETE CASCADE,
	CONSTRAINT `gp_tokens_user_updated_foreign` FOREIGN KEY (`user_updated`) REFERENCES `directus_users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `gp_apps_approvals` (
	`id` char(36) NOT NULL,
	`date_created` timestamp NULL DEFAULT NULL,
	`date_updated` timestamp NULL DEFAULT NULL,
	`user_created` varchar(36) DEFAULT NULL,
	`account_id` varchar(36) DEFAULT NULL,
	`app` char(36) NOT NULL,
	`scopes` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT '[]' CHECK (json_valid(`scopes`)),
	PRIMARY KEY (`id`),
	CONSTRAINT `gp_apps_approvals_account_app_unique` UNIQUE (`user_created`, `app`, `account_id`),
	CONSTRAINT `gp_apps_approvals_account_id_foreign` FOREIGN KEY (`account_id`) REFERENCES `gp_accounts` (`id`) ON DELETE CASCADE,
	CONSTRAINT `gp_apps_approvals_app_foreign` FOREIGN KEY (`app`) REFERENCES `gp_apps` (`id`) ON DELETE CASCADE,
	CONSTRAINT `gp_apps_approvals_user_created_foreign` FOREIGN KEY (`user_created`) REFERENCES `directus_users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
