<?php
  include 'secret.php';
  if($_GET["str1"] and $_GET["str2"]) {
    if ($_GET["str1"] !== $_GET["str2"] and
        hash("md5", $salt . $_GET["str1"]) === hash("md5", $salt . $_GET["str2"])) {
      echo $flag;
    } else {
      echo "Sorry, you're wrong.";
    }
    exit();
  }
?>
<!DOCTYPE html>
<html>
<body style="font-size: 18pt; margin: 10% 10% 10% 10%">
  <p>
    People say that MD5 is broken... But they're wrong! All I have to do is use a secret salt. >:)
  </p>
  <p>
    If you can find two distinct strings that—when prepended with my salt—have the same MD5 hash, I'll give you a flag. Deal?
  </p>
  <p>
    Also, here's the <a href="src">source</a>.
  </p>
  <form method="GET">
    String 1: <input type="text" name="str1" style="font-size: 18pt; margin: 10px 10px 10px 10px">
    <br>
    String 2: <input type="text" name="str2" style="font-size: 18pt; margin: 10px 10px 10px 10px">
    <br>
    <input type="submit" style="font-size: 18pt; margin: 10px 0 10px 0">
  </form>
</body>
</html>