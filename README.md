# traffst

Golang util for quick traffic statistic.
This is pretty useful when you want to check your server for HTTP flood/TCP synflood.


## usage

```
sudo bin/traffst --help
usage: bin/traffst [ -i interface ] [ -s snaplen ] [ -c count ] [ -d enable debug ] [ -h show usage] [ expression ] 
```

## example

```
sudo bin/traffst -i eth1 -c 1000
+----------------+-------+
|       IP       | COUNT |
+----------------+-------+
| 10.0.0.10      | 1000  |
| 64.233.161.141 | 515   |
| 10.0.0.1       | 268   |
| 74.125.232.222 | 115   |
| 173.194.73.95  | 71    |
+----------------+-------+
+-----+-------+
| TTL | COUNT |
+-----+-------+
| 64  | 579   |
| 45  | 311   |
| 55  | 62    |
| 43  | 38    |
| 54  | 8     |
+-----+-------+
+------------+-------+
|    TCP     | COUNT |
+------------+-------+
| 443(https) | 725   |
| 44755      | 515   |
| 40702      | 115   |
| 45152      | 71    |
| 36835      | 10    |
+------------+-------+
+---------------------+-------+
|        HOST         | COUNT |
+---------------------+-------+
| clients1.google.com | 1     |
+---------------------+-------+
```
