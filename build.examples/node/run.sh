#!/bin/bash

# touch debug
# touch upsert 
# touch get 
# touch gets

#/home/dlahuta/go/src/github.com/gravitational/teleport/build.examples/node/pre.sh
rm -rf /home/dlahuta/go/src/github.com/gravitational/teleport/1-node-data
make tp
/home/dlahuta/go/src/github.com/gravitational/teleport/build/teleport start \
    -d -c build.examples/node/teleport.yaml 2>&1 | tee node.log