# gremirror

Creates a port mirror inside a GRE tunnel.  Useful when one needs to create a port mirror and doesn't have access to the necessary network equipment, or when mirroring to a HA VM which may move host ocassionally.

## gretunnel

gretunnel sniffs TCP/UDP packets from an interface and sends them out the same or different interface to the specified destination encapsulated in a GRE header.
```
Usage: gretunnel.exe dst-ip src-ip listen-index send-index
         dst-ip         destination IP address
         src-ip         source IP address
         listen-index   adapter index to listen on
         send-index     adapter index to send on
```
## grestrip

Removes GRE headers from packets.
```
Usage: grestrip.exe iIndex 
         iIndex     adapter index to strip GRE headers from
```

## Installation

1. Install the WinpktFilter runtime from https://www.ntkernel.com/windows-packet-filter/ on source and destination machines
2. On source machine, run gretunnel
3. On destination machine, create firewall exception for GRE (IP protocol 47)
4. On destination machine, run grestrip
 


    
