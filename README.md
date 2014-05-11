ZMQ4 Wireshark Dissector
========================

This is a Lua dissector written for the "new" ZMTP protocol, i.e. ZMTP version
[3.0][zmtp30] and later.

It supports the [NULL][zmtp30] and [PLAIN][plain] authentication mechanisms.

[zmtp30]: http://rfc.zeromq.org/spec:23
[zmtp31]: http://rfc.zeromq.org/spec:37
[plain]:  http://rfc.zeromq.org/spec:24

Installation
------------

This dissector requires Lua 5.2 or newer.

    mkdir -p ~/.wireshark
    cp zmq-dissector.lua ~/.wireshark/
    echo 'dofile("zmq-dissector.lua")' >>~/.wireshark/init.lua

Usage
-----

As ZeroMQ ports are inherently application-specific, you first need to set up the port
range in Preferences → Protocols → ZMQ4.

You can use expression `zmq4` to filter packets. TCP segments are automatically reassembled.

License
-------

See [LICENSE](LICENSE.txt).

Acknowledgements
----------------

This dissector is based on a dissector for ZMTP 2, written by [Robert G. Jakabosky](mailto:bobby@neoawareness.com).
