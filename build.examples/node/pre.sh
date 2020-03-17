#!/bin/bash

# touch debug
# touch upsert 
# touch get 
# touch gets
temp=$(tctl status -c /home/dlahuta/repos/teleport/build.examples/auth/teleport.yaml | grep "CA pin" | awk -F ":" '{print $2}')
sed -i "s/sha256:[^\"]*/sha256:$(echo $temp)/" /home/dlahuta/repos/teleport/build.examples/node/teleport.yaml