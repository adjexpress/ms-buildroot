#!/bin/bash
# set environment variables
source env.sh

function bind_mount(){
    # unlink $CONTAINER_LAB_PATH
    ln -sf $HOST_LAB_PATH $CONTAINER_LAB_PATH
}

function run_image(){
    sudo docker run  \
        --privileged=true  \
        -it \
        -i \
        -e USER_ID=$(id -u) \
        -e GROUP_ID=$(id -g) \
        -v $HOST_SRC_PATH:$CONTAINER_SRC_PATH \
        -v $HOST_LAB_PATH:$CONTAINER_LAB_PATH \
        --ulimit "nofile=1024:1048576" \
        workspace \
        zsh
#         -v /dev:/dev \
}

function start_all(){
    bind_mount
    run_image
}

function cleanup {
  echo "Removing links"
  unlink $CONTAINER_LAB_PATH
}
trap cleanup EXIT
start_all
