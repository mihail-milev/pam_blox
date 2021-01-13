This is a small Linux PAM module written in Rust, which authenticates a given username by searching for a connected Bluetooth device. Depending on the pam.d configuration this module can be used as a 2FA or as a stand-alone authentication mechanism.

# Important about security!

This module is not quite secure, as it checks for the signal strength of a BT device with a givem BT hardware address. BT hardware addresses can be spoofed, so be careful when using this! My intention to write it, is to stop writing 32 character passwords everytime I need sudo. So it is a good idea to configure PAM to use this module, only if the user is already logged in.

# How to use?

Obtain the source code:

    $ git clone https://github.com/mihail-milev/pam_blox.git

Compile the source code:

    $ cargo build --release

Copy the library to your PAM modules folder, e.g.:

    $ sudo cp target/release/libpam_blox.so /usr/lib64/security/pam_blox.so

Create a blox configuration file:

    $ echo -e "username\t00:11:22:33:44:55" | sudo tee /etc/blox_users.conf

The format is "{username}TAB{BT_address}"

Change the configuration file's permissions:

    $ sudo chmod a-rwx,u+rw /etc/blox_users.conf
    $ sudo chown root:root /etc/blox_users.conf

Modify your PAM configuration accordingly, for example I modified /etc/pam.d/system-auth and added the following line in the beginning:

    auth        [success=9 default=ignore]                   pam_blox.so

That's it.

# TODO

1. Make it possible to supply arguments, which can set another path for the configuration file, another BT threshold, etc.
2. Do not execute the hcitool, but use a BT library directly.
