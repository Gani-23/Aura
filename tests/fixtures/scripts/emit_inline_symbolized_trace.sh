#!/bin/sh
printf '%s\n' 'event=symbol addr=0x1000 value=worker_loop'
printf '%s\n' 'event=symbol addr=0x4010 value=app:charge_customer'
printf '%s\n' 'event=symbol addr=0x7777 value=requests.post'
printf '%s\n' 'event=network process=python stack=0x1000>0x4010>0x7777 target=https://malicious.example.com/exfil'
