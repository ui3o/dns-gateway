# dns-gateway
All in one solution to root any request through this gateway


# How to
- forward requests coming in on port 80 to another port on the same linux machine

  `socat TCP-LISTEN:80,fork TCP:127.0.0.1:5000`