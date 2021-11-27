# Aerohive Provision

A little opinionated program to automatically provision my Aerohive APs without HiveManager/ExtremeCloud IQ.

Unfortunately a lot of the config (including passwords) is transmitted in cleartext over the wire, which I'm happy to do in my homelab, but isn't really ideal.

## Running

1. List your APs and desired hostnames in targets.csv.
1. Set your template config in `config.template`.
1. Then run: `go run main.go`

It will interactively ask for:
* Admin password to set
* SSID
* WPA2-PSK
* Hive password (can randomly generate)
* Any credentials required to SSH into the APs

It then renders out the template, hosts it, wipes the APs' bootstrap configuration, tells the AP to pull down the new config and reset itself.