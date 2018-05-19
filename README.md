
see https://www.plixer.com/support/netflow-v5/ for protocol

based on http://blog.devicenull.org/2013/09/04/python-netflow-v5-parser.html

modify the variables

```
INFLUXDB_HOST = "grafana.labs"
INFLUXDB_PORT = 8086
INFLUXDB_DB = "scripts_data"
```

to match your environment. Currently this is doing batch inserts via http on every netflow package (which contains quite a few messages). It could be improved to use UDP.
