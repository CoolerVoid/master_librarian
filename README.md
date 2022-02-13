# master_librarian
<img align="center" src="https://github.com/CoolerVoid/master_librarian/blob/main/doc/castlevania-symphony-of-the-night-alucard-librarian.jpg?raw=true">

A simple tool to audit Unix/*BSD/Linux system libraries to find public security vulnerabilities.

To install requirements:
```
$ sudo python3 -m pip install -r requirements.txt
```
Overview:
```
$ python3 master_librarian.py -h
Master librarian v0.3 
 Tool to search public vulnerabilities on local libraries
by CoolerVoid

Example: 
	$ python3 master_librarian.py -t csv
	$ python3 master_librarian.py -t txt -l 3

usage: master_librarian.py [-h] -t TYPES [-l LIMIT]

optional arguments:
  -h, --help            show this help message and exit
  -t TYPES, --type TYPES
                        Name of output type for logs(txt or csv)
  -l LIMIT, --limit LIMIT
                        Limit CVEs per pages in nvd NIST search(default is 3)

```


Example:
```
$ python3 master_librarian.py -t txt
```
output
```
Master librarian v0.3
 Tool to search public vulnerabilities on local libraries
by CoolerVoid

Example: 
	$ python3 master_librarian.py -t csv
	$ python3 master_librarian.py -t txt -l 3

Master librarian v0.3
 Tool to search public vulnerabilities on local libraries
by CoolerVoid

Search pitfalls in operational system local packages

xres 1.2.0
cairo-ps 1.16.0
xf86vidmodeproto 2.3.1
libcrypto 1.1.1f
damageproto 1.2.1
libffi 3.3
xfixes 5.0.3
		Integer overflow in X.org libXfixes before 5.0.3 on 32-bit platforms might allow remote X servers to gain privileges via a length value of INT_MAX, which triggers the client to stop reading data and get out of sync.
		https://nvd.nist.gov/vuln/detail/CVE-2016-7944
		7.5 HIGH

system.web.extensions.design_1.0 1.0.61025.0
kbproto 1.0.7
gio-unix-2.0 2.64.6
gdk-x11-2.0 2.24.32
sqlite3 3.31.1
cairo-png 1.16.0
libpcre2-posix 10.34
wcf 6.8.0.105
dmxproto 2.3.1
cairo-script 1.16.0
xext 1.3.4
x11 1.6.9
system.web.mvc 1.0.0.0
mono-cairo 6.8.0.105
cecil 6.8.0.105
udev 245
		The default configuration of udev on Linux does not warn the user before enabling additional Human Interface Device (HID) functionality over USB, which allows user-assisted attackers to execute arbitrary programs via crafted USB data, as demonstrated by keyboard and mouse data sent by malware on a smartphone that the user connected to the computer.
		https://nvd.nist.gov/vuln/detail/CVE-2011-0640
		6.9 MEDIUM

		plymouth-pretrigger.sh in dracut and udev, when running on Fedora 13 and 14, sets weak permissions for the /dev/systty device file, which allows remote authenticated users to read terminal data from tty0 for local users.
		https://nvd.nist.gov/vuln/detail/CVE-2010-4176
		4.0 MEDIUM

xkeyboard-config 2.29
bash-completion 2.10
yelp-xsl 3.36.0
xdamage 1.1.5
libgdiplus 6.0.4
icu-uc 66.1
xcomposite 0.4.5
harfbuzz 2.6.4
pixman-1 0.38.4
pthread-stubs 0.4
systemd 245
		An exploitable denial-of-service vulnerability exists in Systemd 245. A specially crafted DHCP FORCERENEW packet can cause a server running the DHCP client to be vulnerable to a DHCP ACK spoofing attack. An attacker can forge a pair of FORCERENEW and DCHP ACK packets to reconfigure the server.
		https://nvd.nist.gov/vuln/detail/CVE-2020-13529
		2.9 LOW

		systemd through v245 mishandles numerical usernames such as ones composed of decimal digits or 0x followed by hex digits, as demonstrated by use of root privileges when privileges of the 0x0 user account were intended. NOTE: this issue exists because of an incomplete fix for CVE-2017-1000082.
		https://nvd.nist.gov/vuln/detail/CVE-2020-13776
		6.2 MEDIUM

		A heap use-after-free vulnerability was found in systemd before version v245-rc1, where asynchronous Polkit queries are performed while handling dbus messages. A local unprivileged attacker can abuse this flaw to crash systemd services or potentially execute code and elevate their privileges, by sending specially crafted dbus messages.
		https://nvd.nist.gov/vuln/detail/CVE-2020-1712
		4.6 MEDIUM

expat 2.2.9
pangocairo 1.44.7
xdmcp 1.1.3
libpcreposix 8.39
ruby-2.7 2.7.0
glib-2.0 2.64.6
gnome-system-tools 3.0.0
xinerama 1.1.4
nunit 2.6.3
gmp 6.2.0
libevent 2.1.11-stable
xbuild12 12.0
xorg-sgml-doctools 1.11
presentproto 1.2
gdk-pixbuf-2.0 2.40.0
inputproto 2.3.2
libssl 1.1.1f
xcb-shm 1.14
gdk-2.0 2.24.32
libpng16 1.6.37
bigreqsproto 1.1.2
icu-io 66.1
xextproto 7.3.0
libthai 0.1.28
libbsd-overlay 0.10.0
mount 2.34.0
gio-2.0 2.64.6
adwaita-icon-theme 3.36.1
fontconfig 2.13.1
xrandr 1.5.2
monosgen-2 6.8.0.105
mono 6.8.0.105
xf86dgaproto 2.1
dri3proto 1.2
libpcre 8.39
pangoxft 1.44.7
blkid 2.34.0
libsepol 3.0
libevent_openssl 2.1.11-stable
uuid 2.34.0
gmodule-2.0 2.64.6
graphite2 3.0.1
libfl 2.6.4
zlib 1.2.11
cairo-pdf 1.16.0
ruby 2.7.0
		Addressable is an alternative implementation to the URI implementation that is part of Ruby's standard library. An uncontrolled resource consumption vulnerability exists after version 2.3.0 through version 2.7.0. Within the URI template implementation in Addressable, a maliciously crafted template may result in uncontrolled resource consumption, leading to denial of service when matched against a URI. In typical usage, templates would not normally be read from untrusted user input, but nonetheless, no previous security advisory for Addressable has cautioned against doing this. Users of the parsing capabilities in Addressable but not the URI template capabilities are unaffected. The vulnerability is patched in version 2.8.0. As a workaround, only create Template objects from trusted sources that have been validated not to produce catastrophic backtracking.
		https://nvd.nist.gov/vuln/detail/CVE-2021-32740
		5.0 MEDIUM

		An issue was discovered in Ruby 2.5.x through 2.5.7, 2.6.x through 2.6.5, and 2.7.0. If a victim calls BasicSocket#read_nonblock(requested_size, buffer, exception: false), the method resizes the buffer to fit the requested size, but no data is copied. Thus, the buffer string provides the previous value of the heap. This may expose possibly sensitive data from the interpreter.
		https://nvd.nist.gov/vuln/detail/CVE-2020-10933
		5.0 MEDIUM

libevent_extra 2.1.11-stable
system.web.mvc3 3.0.0.0
libstartup-notification-1.0 0.12
mono-2 6.8.0.105
mono-nunit 2.6.3
gobject-2.0 2.64.6
glproto 1.4.17
cairo-ft 1.16.0
		cairo 1.16.0, in cairo_ft_apply_variations() in cairo-ft-font.c, would free memory using a free function incompatible with WebKit's fastMalloc, leading to an application crash with a "free(): invalid pointer" error.
		https://nvd.nist.gov/vuln/detail/CVE-2018-19876
		4.3 MEDIUM

xcb 1.14
		Directory traversal vulnerability in Action View in Ruby on Rails before 3.2.22.1, 4.0.x and 4.1.x before 4.1.14.1, 4.2.x before 4.2.5.1, and 5.x before 5.0.0.beta1.1 allows remote attackers to read arbitrary files by leveraging an application's unrestricted use of the render method and providing a .. (dot dot) in a pathname.
		https://nvd.nist.gov/vuln/detail/CVE-2016-0752
		5.0 MEDIUM

fribidi 1.0.8
xtrans 1.4.0
cairo-xlib-xrender 1.16.0
mono-lineeditor 0.2.1
xcmiscproto 1.2.2
gmodule-no-export-2.0 2.64.6
dri2proto 2.8
python3-embed 3.8
libpcre32 8.39
system.web.mvc2 2.0.0.0
dotnet 6.8.0.105
iso-codes 4.4
fontutil 1.3.1
xbitmaps 1.1.1
system.web.extensions_1.0 1.0.61025.0
recordproto 1.14.2
resourceproto 1.2.0
mobile-broadband-provider-info 20190618
videoproto 2.3.3
libevent_core 2.1.11-stable
fontsproto 2.1.3
xsp-4 4.2
python3 3.8
		In Python 3.8.4, sys.path restrictions specified in a python38._pth file are ignored, allowing code to be loaded from arbitrary locations. The <executable-name>._pth file (e.g., the python._pth file) is not affected.
		https://nvd.nist.gov/vuln/detail/CVE-2020-15801
		7.5 HIGH

		In Python 3.6 through 3.6.10, 3.7 through 3.7.8, 3.8 through 3.8.4rc1, and 3.9 through 3.9.0b4 on Windows, a Trojan horse python3.dll might be used in cases where CPython is embedded in a native application. This occurs because python3X.dll may use an invalid search path for python3.dll loading (after Py_SetPath has been used). NOTE: this issue CANNOT occur when using python.exe from a standard (non-embedded) Python installation on Windows.
		https://nvd.nist.gov/vuln/detail/CVE-2020-15523
		6.9 MEDIUM

xineramaproto 1.2.1
xcb-render 1.14
libpcre2-32 10.34
libbsd-ctor 0.10.0
libbsd 0.10.0
		nlist.c in libbsd before 0.10.0 has an out-of-bounds read during a comparison for a symbol name from the string table (strtab).
		https://nvd.nist.gov/vuln/detail/CVE-2019-20367
		6.4 MEDIUM

xft 2.3.3

```

Tested in Ubuntu Linux, Fedora Linux and FreeBSD.

The purpose of this tool is to use in local pentest, take attention if you have a proper authorization before to use that. I do not have responsibility for your actions. You can use a hammer to construct a house or destroy it, choose the law path, don't be a bad guy, remember.
