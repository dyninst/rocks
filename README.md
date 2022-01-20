# This project is no longer maintained

## Rocks

Rocks:  Reliable Sockets, Version 2.4 (September 2002)  
Copyright (c) 2001,2002 Victor C. Zandy  

COPYING contains the distribution terms for rocks (LGPL).

If you are using the source release, please read INSTALL for
instructions on building and installing the rocks binaries.

If you are using the binary release:
  Install rock and rockd somewhere in your default path;
  Install librocks.so in $HOME/lib or somewhere in your LD_LIBRARY_PATH.

### RELEASE OVERVIEW

We support rocks on x86 Linux 2.4.

### ROCKS OVERVIEW

Rocks protect sockets-based applications from network failures,
particularly failures common to mobile computing, including:

 - Link failures (e.g., unexpected modem hangup);
 - IP address changes (e.g., laptop movement, DHCP lease expiry);
 - Extended periods of disconnection (e.g., laptop suspension).

Rock-enabled programs continue to run after any of these events; their
broken connections are restored automatically, without loss of
in-flight data, when connectivity returns.  Rocks can be used with
ordinary sockets-based programs, without re-compiling or re-linking,
including ssh, X windows applications, and network service daemons.
Connections cannot be restored if both ends of the connection change
IP address while disconnected; we are developing another system that
will address this limitation. 

Rocks work entirely at user level: they can be installed and used by
ordinary users and do not require any kernel modifications.

Rocks are transparent to applications.  You can use rocks with
existing programs without re-programming, re-compiling, or re-linking.

Rocks must be present at both ends of the connection.  Rocks detect
peers that are not rock enabled and silently revert to ordinary
sockets.  Rock detection is harmless to the peer.  (But it is not
available on Linux 2.2.)

Rocks are easy to use.  We provide a command-line tool (rock) for
running ordinary programs with rocks.  We also provide a rock daemon
(rockd) to create indirect rock connections with servers that do not
support rocks, such as those owned by root and setuid programs.  These
programs are described in the accompanying manual page rock(1).

Rocks are described in

      V.C. Zandy and B.P. Miller.  Reliable Network Connections.
      ACM MobiCom'02, Altanta, GA, September 2002.

Rocks are one component of the roaming applications system that is
being developed by Victor Zandy and Barton Miller at the University of
Wisconsin - Madison.
