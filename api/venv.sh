#!/bin/bash
if [ ! -f ./requirements.txt ] 
    then
        echo "ERROR: requirements.txt not found"
        return
fi
if [ ! -f ./.virtualenv/bin/activate ]
    then
        pip3 install virtualenv 
        python3 -m virtualenv --python=python3.8 ./.virtualenv
fi
echo Activating virtualenv
source ./.virtualenv/bin/activate
pip3 install --upgrade pip
pip3 install -r ./requirements.txt
