<h1 style="color:#00dabf;font-weight:bold;font-size:21Px;">Network Monitor</h1>
this is a veyr simple script to monitor your network, it will:<br>

- log any new equipement (base on a whitelist)
- check port for requested mac (is your http server up?)
- Send SMS (french Free operator allow this)
- Alert on disconnection / Connection in whitelist

<hr>
basic configuration is in lang.json
Basic whitelist is in Elements/WhiteList.json
<pre>
{
    "B8:27:EB:xx:xx:xx": {
        "CommonName": "RaspberryPI2",       # A human name
        "DNS": "rpi.local",                 # the DNS name
        "IPv4": "192.168.0.3",              # IP v4
        "Mac": "B8:27:EB:xx:xx:xx",         # MAc Adress
        "Options": "NoCoAlertNoDiscoAlert", # Options
        "Check":[80],                       # Do port Check/protocol Check
        "Grace_Count":3                     # Alert after x successive
    }
}
</pre>