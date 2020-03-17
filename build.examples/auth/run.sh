#!/bin/bash

# rm debug
# rm upsert 
# rm get 
# rm gets
rm -rf /home/dlahuta/go/src/github.com/gravitational/teleport/1-auth-data
rm build/teleport
make tp
build/teleport start -d -c build.examples/auth/teleport.yaml.backup 2>&1 | tee auth.log