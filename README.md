PlayStation 4 Discovery and Wake-up Utility
===========================================
Copyright (C) 2014 Darryl Sokoloski <darryl@sokoloski.ca>

Copyright (C) 2018 Fariouche <fariouche@yahoo.fr> for the additions (connect, login, suspend, start app)

Thanks to @dhleong, maintainer of ps4-waker (https://github.com/dhleong/ps4-waker), where all the protocol stuff was inspired from.


Build & Install
---------------
You can build and install the binary using the following command chains.

    # aclocal && autoheader && automake --add-missing && autoconf
    # ./configure && make && sudo make install

Successfully built and run this way on Raspberry Pi with _Raspbian GNU/Linux 9 (stretch)_.


Requirements
------------
In order to wake your PS4 remotely, the PS4 must be in Standby mode. Check the power management settings to enable Standby mode.

If you just wish to see the current status of your PS4, you do not require a "user credential" number.

For wake-up support, you need to obtain a "user credential" which requires a Vita that has already been paired with the PS4.  You then need to capture and examine the initial few UDP packets sent from the Vita when launching the PS4 Link application.  Under Unix-like (Linux, BSD, OSX) operating systems you can use tcpdump.  The traffic must be captured from your home network's gateway in order to see these packets.  Ensure the Vita is connecting to the PS4 through it's wired interface.

An example capture using tcpdump:

    # tcpdump -s0 -X -n -i <interface> udp and port 987

You'll be looking for a packet that looks like HTTP and contains the string 'user-credential:NNNNNNN'.  Remember the "user credential" number.

You can use the ps4-waker nodejs application to fake a standby ps4 and retrieve the user credential.
If something is not working, this is most likely a user credential problem. (it is a very long 64 characters string)

Why not use the python or nodejs applications? Juste because they are way too big in size (30MB or 100MB juste to wakeup a ps4... this is overkill). ps4-wake juste takes 90KB and does not pull any dependency.


Usage Overview
--------------

     Probe:
      -P, --probe
        Probe network for devices.
     
     Wake:
      -W, --wake
        Wake device.
     
     Standby:
      -S, --standby
        put the device in standby mode.
     
     Options:
      -c, --credential <user-credential>
        use specified user credential (needed by wake and login).
      -l, --login
        login to the device.
      -p, --passcode
        use passcode when login (must be used with login option).
      -B, --broadcast
        Send broadcasts.
      -L, --local-port <port address>
        Specifiy a local port address.
      -H, --remote-host <host address>
        Specifiy a remote host address.
      -R, --remote-port <port address>
        Specifiy a remote port address (default: 987).
      -I, --interface <interface>
        Bind to interface.
      -j, --json
        Output JSON.
      -v, --verbose
        Enable verbose messages.

Examples
--------
To search your whole network for a PS4:

    # ./ps4-wake -vP -B

To search via broadcasts using a specific network interface, eth0 for example:

    # ./ps4-wake -vP -B -I eth0

To send a probe directly to the PS4 using it's IPv4 address, 192.168.1.10 for example:

    # ./ps4-wake -vP -H 192.168.1.10

To wake-up your PS4 using your 64 chars "user credential" string:

    Via broadcast:
    # ./ps4-wake -vW -c <64 chars credential> -B

    Or, direct:
    # ./ps4-wake -vW -c <64 chars credential> -H 192.168.1.10

To wakeup and login and start an application:

    # ./ps4-wake -vW -c <64 chars credential> -B -l -s <application ID>

To retrieve the application id, start the application the normal way and execute:
    
    # ./ps4-wake -v -B -P

