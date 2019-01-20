#!/bin/bash

# This script enables sharing of single screens in Chromium-based applications on systems with more than one monitor.
# Chromium screen sharing treats multiple monitors as one big monitor.  This script uses the v4l2-loopback
# module to create a virtual webcam of the monitor you want to share.

# The script is based off of the vlc-hangouts script available here: https://github.com/Ashark/hliss/blob/master/vlc-hangouts

# This script has not been tested on Wayland.

# Requires the v4l2-loopback module, available from:
# Arch AUR: v4l2-loopback-dkms-git
# Debian / Ubuntu: v4l2loopback-dkms
# Others: https://github.com/umlaeute/v4l2loopback

# Requires xrandr, available from:
# Arch official repositories: xorg-xrandr
# Debian / Ubuntu: x11-xserver-utils

# Requires ffmpeg, available from:
# Arch official repositories: ffmpeg
# Debian / Ubuntu: Use avconv (libav-tools) and modify this script or deb-multimedia.org
# Fedora: ffmpeg from RPMFusion

echo "Setting up v4l2-loopback"
sudo rmmod v4l2loopback 2> /dev/null
sudo modprobe v4l2loopback video_nr=7 'card_label=Screen Mirror'

xrandr --listactivemonitors
read -p "Which monitor do you want to share? " MON_NUMBER

MON_PARSE=`xrandr --listactivemonitors | grep "$MON_NUMBER:" | cut -f4 -d' '`
MON_HEIGHT=`echo $MON_PARSE | cut -f2 -d'/' | cut -f2 -d'x'`
MON_WIDTH=`echo $MON_PARSE | cut -f1 -d'/'`
MON_X=`echo $MON_PARSE | cut -f2 -d'+'`
MON_Y=`echo $MON_PARSE | cut -f3 -d'+'`

# have to scale to 1920x1080 to work with Discord (-vf)
# -r 30: 30 frames per second
# -s: Capture the monitor's width and height found via xrandr earlier
# -i: Capture starting from the coordinates on the "one large screen"
ffmpeg -f x11grab -r 30 -s "$MON_WIDTH"x"$MON_HEIGHT" -i $DISPLAY.0+"$MON_X","$MON_Y" -vcodec rawvideo -pix_fmt yuv420p -vf "scale=1920:1080" -threads 0 -f v4l2 /dev/video7

# Remove v4l2loopback
echo "Unloading v4l2-loopback"
sudo rmmod v4l2loopback
