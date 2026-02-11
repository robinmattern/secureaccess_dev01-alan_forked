#!/bin/bash

   aPort="55351";     
   nPort="54532";    
   aStg="server"    
   aApp="s01_server-first-api"
#  aSvr="server.mjs"
   aSvr="server.js"

#  aMode="dev"      # or start for prod, or build

function Help() {
if [ "$1" != "" ]; then
    echo -e "\n* Invalid App: $1"; else echo ""; fi
    echo "Usage:                   Use .env file:"
    echo "  ./run-server           Currently in ./api folder"
    echo "  ./run-server set {loc} Set location to local, remote or custom"
    echo "  ./run-server local    ./api/.env-local.env file"
    echo "  ./run-server remote   ./api/.env-remote.env file"
    echo "  ./run-server custom   ./api/.env-custom.env file"
    if [ "${OS:0:3}" != "Win" ]; then echo ""; fi; exit;  
    }

  if [ "$1" == "help"   ]; then Help; exit; fi; bOK=0 
  if [ "$1" == "local"  ]; then aCmd=$1; bOK=1; fi 
  if [ "$1" == "remote" ]; then aCmd=$1; bOK=1; fi 
  if [ "$1" == "custom" ]; then aCmd=$1; bOK=1; fi 
  if [ "$1" == "set"    ]; then aCmd=$1; bOK=1; fi 
  if [ "$1" == ""       ]; then aCmd="same"; bOK=1; fi 
  if [ "${bOK}" != "1"  ]; then Help $1; exit; fi; 

  if [ "${aCmd}" == "set"  ]; then aCmd="$2"; bOK=1; fi 
  if [ "${aCmd}" == "same" ]; then echo "not copying .env"; bOK=1; fi 
  if [ "${aCmd}" != "same" ]; then 
    echo -e "\n  Copying ./api/.env-${aCmd}.env to ./api/.env"
    cp -p "./api/.env-${aCmd}.env" "./api/.env"  
    if [ "${2}" != "" ]; then if [ "${OS:0:3}" != "Win" ]; then echo ""; fi; exit; fi 
    fi 
 
          aPath="$(realpath "$0")"; aPath="${aPath/\/run-server/}";  # echo "  ${aPath}"
    cd "${aPath}" 

          NODEMON="../node_modules/.bin/nodemon"; NODEMON=$( ls -1 "${NODEMON}" );  echo "NODEMON: ${NODEMON}"; # exit 
# if [ ! -f "${NODEMON}" ]; then NODEMON=node; fi
  if [ "${NODEMON}" == "" ]; then NODEMON=node; fi

 echo -e "\n# ${NODEMON/*\//} ${aSvr} ${nPort}"  
 echo    "------------------------------------------------------------------------------------"
#echo    "  ${aPath}"
#echo    ""
#exit
        chromePath=$(which chrome 2>/dev/null)
if [ "${chromePath}" != "" ]; then chrome  "http://localhost:${aPort}"; fi

echo "${NODEMON}" ${aSvr}  ${aPort}
     "${NODEMON}" ${aSvr}  ${aPort}
