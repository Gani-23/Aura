#!/bin/sh
printf '%s\n' 'event=network function=charge_customer process=python target=https://api.stripe.com/v1/charges'
printf '%s\n' 'event=network function=charge_customer process=python target=https://malicious.example.com/exfil'
