##Security.class.php 
-----------------

Script allows you to secure our website.
All you need to do to start using this class is to initialize it like in **index.php** file. 

How class is built?
-----------------

Class has 11 method and 1 property. 

Methods:
- `init()` 
- `isAjax()`
- `xssClean()`
- `request()`
- `clean()` 
- `urlClean()`
- `hashPassword()`
- `checkPassword()`
- `passwordNeedsRehash()`
- `getPasswordInfo()`

Properties:
- `$config` private property, that is consisted of two keys: *error_reporting*, *path* (check config.class.php)
