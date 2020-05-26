## network: TACACS+

find the key (cisco type 7) in the tftp config: (with filter `tftp`, the right click, follow UDP stream.)

tacacs-server host 192.168.1.100 key 7 0325612F2835701E1D5D3F2033

http://ibeast.com/tools/CiscoPassword/index.asp

decrypted:
AZDNZ1234FED

then use wireshark->preferences->protocols->TACACS+ and enter the key

find the packets in tcp.
