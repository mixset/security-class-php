<?php
/**
 * @author Dominik Ryńko <http://www.rynko.pl/>
 * @version 1.0
 * @license http://creativecommons.org/licenses/by-sa/3.0/pl/
 */

// Set default charset and document type
header('Content-Type: text/html; charset=UTF-8');

// Check PHP version
if(version_compare(PHP_VERSION, '5.4.0') <= 0)
{
 exit('Script requires 5.4.0 or higher version of PHP. My version is: '.PHP_VERSION);
}

$className = 'security.class.php';

if(file_exists($className) && filesize($className) !== 0)
{
 require $className;

 $config = ['error_reporting' => ['E_ALL', 1], 'path' => '/'];
 $security = new Security\Security($config);
 echo $security -> init();

 /**
  isAjax() method demo
 */
  if($security -> isAjax() == true) {
      echo 'Request comes from AJAX';
  } else {
      echo 'Request does not comes from AJAX';
  }

  $xss = '<img src="http://url.to.file.which/not.exist" onerror=alert(document.cookie);>';

  echo 'Code after cleaning<br>';
  echo $security -> clean($xss);
  echo '<br><br>';

  echo 'Code after xssClean method sanitizing';
  var_dump($security -> xssClean($xss));

  echo '<br><br>';
  echo 'Code, that checks if request comes from POST type<br>';
  echo ($security -> request('POST') ? 'POST' : 'GET').'<br>';

  echo '<br><br>';
  // Simple text in polish
  $string = 'Świetny artykuł, <strong>poza tym</strong> polecam tą stronę: <a href="http://google.pl" title="tytuł">Link</a>';
  echo 'After cleaning<br>';
   var_dump($security -> clean($string));
} else {
    return 'File: '. $className.' does not exist. Cannot load module.';
}


?>