##
## turbine-security-data.sql
##
## Torque will not autogenerate these files anymore - please run
## this SQL code maually to get your application up and running
##
SET FOREIGN_KEY_CHECKS=0;

INSERT INTO TURBINE_USER (USER_ID,LOGIN_NAME,PASSWORD_VALUE,FIRST_NAME,LAST_NAME,EMAIL)
    VALUES (1,'admin','password','','Admin','');

INSERT INTO TURBINE_USER (USER_ID,LOGIN_NAME,PASSWORD_VALUE,FIRST_NAME,LAST_NAME,EMAIL)
    VALUES (2,'user','password','','User','');
    
INSERT INTO TURBINE_USER (USER_ID,LOGIN_NAME,PASSWORD_VALUE,FIRST_NAME,LAST_NAME,EMAIL)
    VALUES (3,'anon','nopw','','Anon','');

INSERT INTO `TURBINE_PERMISSION` (`PERMISSION_ID`, `PERMISSION_NAME`) VALUES
(2, 'Turbine'),
(1, 'TurbineAdmin');

INSERT INTO `TURBINE_ROLE` (`ROLE_ID`, `ROLE_NAME`) VALUES
(1, 'turbineadmin'),
(2, 'turbineuser');

INSERT INTO `TURBINE_GROUP` (`GROUP_ID`, `GROUP_NAME`) VALUES
(1, 'global'),
(2, 'Turbine');

INSERT INTO `TURBINE_ROLE_PERMISSION` (`ROLE_ID`, `PERMISSION_ID`) VALUES
(1, 1),
(2, 2);

INSERT INTO `TURBINE_USER_GROUP_ROLE` (`USER_ID`, `GROUP_ID`, `ROLE_ID`) VALUES
(1, 1, 1),
(1, 2, 1),
(2, 2, 2),
(2, 1, 2);
