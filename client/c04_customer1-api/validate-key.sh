#!/bin/bash

# curl -X GET http://localhost:57353/api/users \
#   -H "Origin: http://localhost:51205" \
#   -H "X-API-Key: key_a8071f32c0086c801561ce6b93349af5"


  curl "http://localhost:57353/api/validate?appId=APIapp1" \
    -H "Origin: http://localhost:51200" \
    -H "X-API-Key: key_a8071f32c0086c801561ce6b93349af5"