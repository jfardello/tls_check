
# TLS Check

TLS Check is a tool for monitoring server certificates, it can monitor
expiry time and a certificate change by calculating the sha256.

If you use different certificates for the same service , you can add all the
sha256 values to the list:

``site.com sha256_value1 sha256_value2``

## Usage
You can pass a list of hosts in a file as an argument or as stdin.

```
$ CHECK_DAYS=5 ./tls_check.py <<EOM
app.site.com bc937c50d0ce6e7d1011fe6dc90bb943ed09faa5a294ca8f7a2e692dd1e45f62
app2.site2.net 6e40ba1a8caafd4ddbca949bb5505754fe1a09899314f33d4e976162ecfb2303
EOM

INFO:TLSCheck:app.site.com cert is fine
INFO:TLSCheck:app2.site2.net cert is fine
$ echo $?
0
```

or

```
./tls_check.py hostlist.txt
```
Config options are environment variables:

* CHECK_DAYS:
  The minimun allowed ramaining days to the expiry date.
* LOGLEVEL:
  INFO (defaul), DEBUG, ERROR, etc..(as in python's logging module.)
