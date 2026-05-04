#!/bin/sh
printf '%s\n' 'event=network process=python stack=0x1000>0x4010>0x7777 target=https://malicious.example.com/exfil'
