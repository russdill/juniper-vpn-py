#! /usr/bin/env python3

import warnings

if __name__ == '__main__':
    warnings.warn('Please use the shim created by pip when installing the junipervpn package. If you use a virtualenv, it will be in PATH after activating it')

    # Import after the warning, so the warning is the first thing seen rather
    # than some ImportError due to some missing packages
    from junipervpn import vpn
    vpn.main()
