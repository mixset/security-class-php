<?php
/**
 * @author Dominik Ryńko <http://www.rynko.pl/>
 * @version 1.0.0
 * @license http://creativecommons.org/licenses/by-sa/3.0/pl/
 */

// Set default charset and document type
header('Content-Type: text/html; charset=utf-8');

// Check PHP version
if(version_compare(PHP_VERSION, '5.4.0') <= 0)
{
 exit('Script requires 5.4.0 or higher version of PHP. My version is: '.PHP_VERSION);
}

$className = 'security.class.php';

if(file_exists($className) && filesize($className) !== 0)
{
 require $className;

 $security = new security();
 $security -> config['domain'] = 'http://127.0.0.1/';
 $security -> config['error_reporting'] = 'E_ALL';
 echo $security -> init();

 /**
  isAjax() method demo
 */
  if($security -> isAjax() == true)
   echo 'Request zostal wywołany za pomocą AJAXa';
  else
   echo 'Request NIE został wywołany za pomocą AJAXA';

  echo "<br></br>";

  $xss = '<img src="http://url.to.file.which/not.exist" onerror=alert(document.cookie);>';

  echo 'Kod HTML, który nie był filtrowany:<br>';
  echo $security -> clean($xss);
  echo '<br><br>';

  echo 'Kod HTML, który zostal przepuszczony przez filtr:';
  var_dump($security -> xssClean($xss));

  echo '<br><br>';
  echo 'Przykładowy kod, który sprawdza czy request nastąpił za pomocą POST<br>';
  echo 'Wywołano za pomocą: <b>'.($security -> request('POST') ? 'POST' : 'GET').'</b><br>';

  echo '<br><br>';
  echo 'Przykładowy kod HTML, który został przepuszczony przez methodę clean()<br>';
  $string = 'Świetny artykuł, <strong>poza tym</strong> polecam tą stronę: <a href="http://google.pl" title="tytuł">Link</a>';
  echo 'Po filtracji<br>';
  echo var_dump($security -> clean($string));
}
else
{
 return 'File: '. $className.' does not exist. Cannot load module.';
}


?>