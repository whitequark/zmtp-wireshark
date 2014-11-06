ZMTP Wireshark Dissector
========================

This is a Lua dissector written for the "new" ZMTP protocol, i.e. ZMTP version
[3.0][zmtp30] and later.

It supports the [NULL][zmtp30] and [PLAIN][plain] authentication mechanisms.

[zmtp30]: http://rfc.zeromq.org/spec:23
[zmtp31]: http://rfc.zeromq.org/spec:37
[plain]:  http://rfc.zeromq.org/spec:24

Screenshot
----------

![Screenshot](/screenshot.png)

Installation
------------

This dissector requires Lua 5.2 or newer.

    mkdir -p ~/.wireshark/plugins
    git clone git://github.com/whitequark/zmtp-wireshark ~/.wireshark/plugins/zmtp-wireshark

Usage
-----

As ZeroMQ ports are inherently application-specific, you first need to set up the port
range in Preferences → Protocols → ZMTP.

You can use expression `zmtp` to filter packets. TCP segments are automatically reassembled.

If you get frame errors, especially when capturing on `lo`, the problem is that libpcap cannot capture packets over 64 KiB (relevant [bug](https://github.com/the-tcpdump-group/tcpdump/issues/389)); do `sudo ip link set lo mtu 65500`.

Subdissectors
-------------

This dissector supports calling subdissectors for an application-level protocol. As ZMTP does
not have a generic way of specifying the inner protocol, it is necessary to specify the protocol
in the preferences.

A subdissector that wishes to observe ZMTP frames must register itself in the `zmtp.protocol`
dissector table.

License
-------

See [LICENSE](LICENSE.txt).

Acknowledgements
----------------

This dissector is based on a dissector for ZMTP 2, written by [Robert G. Jakabosky](mailto:bobby@neoawareness.com).
