CREATE TABLE IF NOT EXISTS directus_users (
	id CHAR(36) PRIMARY KEY,
	github_username VARCHAR(255)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `gp_apps` (
	`id` char(36) NOT NULL,
	`user_created` char(36) DEFAULT NULL,
	`date_created` timestamp NULL DEFAULT NULL,
	`user_updated` char(36) DEFAULT NULL,
	`date_updated` timestamp NULL DEFAULT NULL,
	`name` varchar(255) DEFAULT NULL,
	`owner_name` varchar(255) NULL DEFAULT NULL,
	`owner_url` varchar(255) NULL DEFAULT NULL,
	`secret` varchar(255) DEFAULT NULL,
	`redirect_urls` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin CHECK (json_valid(`redirect_urls`)),
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
	`value` varchar(255) DEFAULT NULL,
	`app_id` char(36) DEFAULT NULL,
	`scopes` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT '[]' CHECK (json_valid(`scopes`)),
	`type` varchar(255) DEFAULT 'access_token',
	`parent` int(10) unsigned DEFAULT NULL,
	PRIMARY KEY (`id`),
	UNIQUE KEY `gp_tokens_value_unique` (`value`),
	KEY `gp_tokens_user_created_foreign` (`user_created`),
	KEY `gp_tokens_user_updated_foreign` (`user_updated`),
	KEY `value_index` (`value`),
	KEY `gp_tokens_app_id_foreign` (`app_id`),
	KEY `gp_tokens_parent_foreign` (`parent`),
	CONSTRAINT `gp_tokens_app_id_foreign` FOREIGN KEY (`app_id`) REFERENCES `gp_apps` (`id`) ON DELETE CASCADE,
	CONSTRAINT `gp_tokens_parent_foreign` FOREIGN KEY (`parent`) REFERENCES `gp_tokens` (`id`) ON DELETE CASCADE,
	CONSTRAINT `gp_tokens_user_created_foreign` FOREIGN KEY (`user_created`) REFERENCES `directus_users` (`id`) ON DELETE CASCADE,
	CONSTRAINT `gp_tokens_user_updated_foreign` FOREIGN KEY (`user_updated`) REFERENCES `directus_users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
