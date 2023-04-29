<?php
  if($_GET["auth"]) {
    if ($_GET["auth"] === "true") {
      echo "Here you go: actf{why_did_you_get_me}";
    } else {
      echo "Hey, you're not authorized!";
    }
    exit();
  }
?>
<!DOCTYPE html>
<html>
<body style="font-size: 18pt; margin: 10% 10% 10% 10%">
  <p>
    Get me! (if you're authorized)
  </p>
  <form method="GET">
    <input type="hidden" name="auth" value="false">
    <input type="submit" value="Submit">
  </form>
</body>
</html>