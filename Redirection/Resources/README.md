### Flag sur redirection sur Instagram, Facebook, Twitter
# on change le lieu de redirection
http://localhost:8080/index.php?page=redirect&site=facebook
a 
http://localhost:8080/index.php?page=redirect&site=facebook.tmp.tmp


grace a des addresses de spider recherche
wget --spider -r -l inf http://localhost:8080 2>&1 | tee spider.txt