# systemd deployment

On Linux, open a root shell once:

```sh
sudo -i
```

Download and verify the latest binary in that shell:

```sh
case "$(uname -s)" in
  Linux*) OS=linux ;;
  Darwin*) OS=darwin ;;
  MINGW*|MSYS*|CYGWIN*) OS=windows; EXT=.exe ;;
  *) exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) exit 1 ;;
esac

BIN="./guassp${EXT:-}"
curl -#SfLo "$BIN" \
  "https://github.com/WoozyMasta/guassp/releases/latest/download/guassp-$OS-$ARCH${EXT:-}"
chmod +x "$BIN"
"$BIN" -v
```

Create the service user, generate the configuration with the binary,
and edit the config and environment file:

```sh
install -m 0755 ./guassp /usr/local/bin/guassp
useradd --system --user-group --no-create-home --shell /usr/sbin/nologin guassp
install -d -o root -g guassp -m 0750 /etc/guassp
/usr/local/bin/guassp /etc/guassp/guassp.yaml
chown root:guassp /etc/guassp/guassp.yaml
chmod 0640 /etc/guassp/guassp.yaml
install -o root -g guassp -m 0640 /dev/null /etc/guassp/guassp.env
editor /etc/guassp/guassp.yaml
editor /etc/guassp/guassp.env
```

The first config command writes an example
and exits with a message asking you to configure it.
Set the GitLab and SonarQube URLs in the config,
then add `GITLAB_TOKEN`, `SONARQUBE_TOKEN`, and `WEB_PASSWORD`
to the environment file.

Create the unit, then start the service:

```sh
cat > /etc/systemd/system/guassp.service <<'EOF'
[Unit]
Description=GUASSP - GitLab User Access Synchronization for SonarQube Projects
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=guassp
Group=guassp
WorkingDirectory=/etc/guassp
EnvironmentFile=/etc/guassp/guassp.env
ExecStart=/usr/local/bin/guassp /etc/guassp/guassp.yaml
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now guassp
systemctl status guassp
```

Follow service logs with `journalctl --unit guassp --follow`.
