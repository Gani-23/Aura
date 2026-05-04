#!/bin/sh
printf '%s\n' 'event=context conn_id=conn-1 traceparent=00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01 request_id=req-123'
printf '%s\n' 'event=network process=python comm=python conn_id=conn-1 target=https://api.stripe.com/v1/charges'
printf '%s\n' 'event=network process=python comm=python conn_id=conn-1 target=https://malicious.example.com/exfil'
