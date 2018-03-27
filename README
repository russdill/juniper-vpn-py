Connecting to a Juniper VPN requires the generation of a DSID token.
Generating this token involves authentication and host checking. The
juniper-vpn.py script performs authentication, and the tncc.py script
performs host checking. The DSID token can then be passed to openconnect.

Alternatively, openconnect can perform the authentication steps on it's own
and utilize the tncc.py script for host checker functionality. This is
the recommended mode of operation. Instructions for using openconnect to
perform authentication and tncc.py to perform host checking are contained in:

README.host_checker

Alternate instructions to allow juniper-vpn.py to perform authentication and
tncc.py to perform host checking are contained in:

README.authenticator

Python dependencies can be found at `requirements.txt` file.
