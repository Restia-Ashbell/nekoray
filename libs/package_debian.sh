#!/bin/bash

version="$1"

mkdir -p nekoray/DEBIAN
mkdir -p nekoray/opt
cp -r linux64 nekoray/opt
mv nekoray/opt/linux64 nekoray/opt/nekoray

# basic
cat >nekoray/DEBIAN/control <<-EOF
Package: nekoray
Version: $version
Architecture: amd64
Maintainer: Mahdi Mahdi.zrei@gmail.com
Depends: desktop-file-utils
Description: Qt based cross-platform GUI proxy configuration manager (backend: sing-box)
EOF

cat >nekoray/DEBIAN/postinst <<-EOF
cat >/usr/share/applications/nekoray.desktop<<-END
[Desktop Entry]
Name=nekoray
Comment=Qt based cross-platform GUI proxy configuration manager (backend: sing-box)
Exec=sudo /opt/nekoray/launcher
Icon=/opt/nekoray/nekobox.png
Terminal=false
Type=Application
Categories=Network;Application;
END

setcap cap_sys_admin=ep /opt/nekoray/launcher

update-desktop-database
EOF

sudo chmod 0755 nekoray/DEBIAN/postinst

# desktop && PATH

sudo dpkg-deb --build nekoray
