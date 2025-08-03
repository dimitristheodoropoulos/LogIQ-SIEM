#!/bin/bash

USERNAME=$(whoami)
PROJECT_DIR=$(pwd)
VENV_PATH="$PROJECT_DIR/venv/bin/python3"
MAIN_PY="$PROJECT_DIR/main.py"

cat <<EOF | sudo tee /etc/systemd/system/logiq.service
[Unit]
Description=LogIQ Flask API Service
After=network.target

[Service]
User=$USERNAME
WorkingDirectory=$PROJECT_DIR
ExecStart=$VENV_PATH $MAIN_PY
Restart=always
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable logiq
sudo systemctl restart logiq
