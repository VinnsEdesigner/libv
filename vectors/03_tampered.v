v device nokia-c22-03
vv org attacker-org
vv name Bench 3
vv cloud
vvv ws wss://api.vyzorix.com/ws/device
vvv hb 30s
vvv backoff 1s>30s
vv apps root /data/local/vyzorix-apps > /home/apps autostart true
vvv app flasher-server 3000
vvvv cmd npm start -- --port 3000
v sig ecdsa-p256 MEYCIQDY+43FhUP2eCafZtdQGjjabDA2y03G51G1Hn4+llsKswIhAN+DaFPwwuqvMQ2rGE4Z2u9CmwFTo0hOWI+l6JksrAJA
