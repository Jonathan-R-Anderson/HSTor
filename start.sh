#!/bin/bash
set -e

TOR_INSTANCES=${TOR_INSTANCES:-3}
BASE_SOCKS_PORT=${BASE_SOCKS_PORT:-9050}
BASE_CONTROL_PORT=${BASE_CONTROL_PORT:-10050}

mkdir -p /tor

echo "Starting $TOR_INSTANCES Tor instances..."

for ((i=0;i<$TOR_INSTANCES;i++))
do
    SOCKS_PORT=$((BASE_SOCKS_PORT + i))
    CONTROL_PORT=$((BASE_CONTROL_PORT + i))

    mkdir -p /tor/tor$i/data

cat <<EOF > /tor/tor$i/torrc
SocksPort $SOCKS_PORT
ControlPort $CONTROL_PORT
DataDirectory /tor/tor$i/data
Log notice stdout
EOF

    tor -f /tor/tor$i/torrc &
done

echo "Waiting for Tor circuits..."
sleep 10

echo "Starting proxy server..."
python3 /proxy_pool.py