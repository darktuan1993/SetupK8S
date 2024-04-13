# json_data="/root/tt/test.json"
# name=$(jq -r '.items' "$json_data")
# echo "$name" > output.json
# jsonItem="/root/tt/output.json"
# new_array=$(cat "$jsonItem" | jq )
# array_length=$(echo "$new_array" | jq length)
# echo $array_length
# for ((i = 0; i < $array_length; i++)); do
#     item=$(echo "$new_array" | jq ".[$i]")
#     spec=$(echo "$item" | jq ".spec")
#     echo "Phần tử thứ $i:"
#     echo "$spec"
# done
# crontab 
# test.txt
# echo "1 $date" >> test.txt



curl -skSL https://raw.githubusercontent.com/kubernetes-csi/csi-driver-nfs/v4.5.0/deploy/install-driver.sh | bash -s v4.5.0 --
