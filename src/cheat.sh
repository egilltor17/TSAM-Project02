#!/bin/bash

echo knock | nc -u skel.ru.is 4096 &
PID=$!
sleep 0.1
kill -9 $PID


echo knock | nc -u skel.ru.is 4095 &
PID=$!
sleep 0.1
kill -9 $PID

echo knock | nc -u skel.ru.is 4096 &
PID=$!
sleep 0.1
kill -9 $PID

echo knock | nc -u skel.ru.is 4096 &
PID=$!
sleep 0.1
kill -9 $PID

# echo knock | nc -u skel.ru.is 4095 &
# PID=$!
# sleep 0.1
# kill -9 $PID

# echo How mutch wood could a woodchuck chuck if a woodchuck could chuck wood! | nc -u skel.ru.is 4095

# 4096,4095,4096,4096,4095