CREATE TABLE `passwd` (
    `user` text NOT NULL,
    `password` text NOT NULL,
    `enabled` tinyint(1) NOT NULL default '1',
    PRIMARY KEY  (`user`)
);

INSERT INTO `passwd` VALUES ('proxy-user', 'proxy-password', 1);
