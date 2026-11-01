    v device nokia-c22-03
    vv org vyzorix-workshop-kisumu
    vv name Bench 3
    vv cloud
    vvv ws wss://api.vyzorix.com/ws/device
    vvv hb 30s
    vvv backoff 1s>30s
    vv apps root /data/local/vyzorix-apps > /home/apps autostart true
    vvv app flasher-server 3000
    vvvv cmd npm start -- --port 3000
v sig ecdsa-p256 MEQCICP8wX5KCm4HSl0RvRCoLuv6CCWypBfXVTiaUIUGaWN6AiAJVEApUybVXJ2tp9a5zXhv78JHnkmxTxJYNP2TkA7bsg==
