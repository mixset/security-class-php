# Security class for PHP

[![Build Status](https://travis-ci.org/mixset/security-class-php.png)](https://travis-ci.org/mixset/security-class-php)

Class provides you basic methods, that secures your system.  

## How to use

Simply, run `git clone git@github.com:mixset/security-class-php.git` in your core or lib directory.

Then, use `include`, `require` or `__autoload()` function, to add Security class to your project. 


To run tests locally, install dependencies by `composer install`.
It will install latest `phpunit` for php 5.6 version.

##  Contributing

If you have any idea how application can be improved, please create new issue with detailed description of your idea. Thank you :)

## Change log
[03.12.2015] v1.0
* Class release

[27.05.2018] v1.1
* Added setters and getters for app configuration
* URL and E-mail filters added 
* Custom exception created
* Clean up