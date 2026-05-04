#!/bin/sh
printf '%s\n' 'event=network process=python comm=python target=https://api.stripe.com/v1/charges'
printf '%s\n' 'event=network process=python comm=python target=https://malicious.example.com/exfil'
