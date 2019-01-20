This script enables sharing of single screens in Chromium-based applications on systems with more than one monitor.

Chromium screen sharing treats multiple monitors as one big monitor.  This script uses the v4l2-loopback module to create a virtual webcam of the monitor you want to share.

The script is based off of the vlc-hangouts script available [here](https://github.com/Ashark/hliss/blob/master/vlc-hangouts)

**This script has not been tested on Wayland.**

# Requirements

  * ```v4l2-loopback module```
    * Arch AUR: ```v4l2-loopback-dkms-git```
    * Debian / Ubuntu: ```v4l2loopback-dkms```
    * Others (source code available): https://github.com/umlaeute/v4l2loopback

  * ```xrandr```
    * Arch official repositories: ```xorg-xrandr```
    * Debian / Ubuntu: ```x11-xserver-utils```
    * Fedora: should be installed by default

  * ```ffmpeg```
    * Arch official repositories: ffmpeg
    * Debian / Ubuntu: Use ```avconv``` (```libav-tools```) and modify this script or ```ffmpeg``` from deb-multimedia.org
    * Fedora: ```ffmpeg``` from RPMFusion

# Usage
Run the script
```bash
./setup_virtualscreen.sh
```

Choose the monitor you would like to capture, and you should be good to go.  The script works even if Discord is running.  It will show up as a webcam.
