# -*- coding: utf-8 -*- 
from flask import Flask
from flask import make_response,request,redirect
from flask_sockets import Sockets
from datetime import datetime
from requests import get,post
import re,struct,gc
# from gevent import socket
from gevent import socket
import gevent

application = Flask(__name__)
sockets = Sockets(application)
app.total = 0
IMPLEMENTED_METHODS = (2, 0)

def ws_remote(ws,remote):
    while True:
        try:
            message = ws.receive()
            remote.sendall(message)
            del message
        except Exception as e:
            break
    ws.close()
    remote.close()

def local_ws(ws,remote):
    while True:
        try:
            r_message = remote.recv(4096)
            if r_message:
                ws.send(r_message)
                del r_message
            else:
                del r_message
                break
        except Exception as e:
            break
    remote.close()
    ws.close()            


def handshake(ws):
    try:
        recv = ws.receive()
        if recv[0] != 5:
            return False
        
        send_msg = (b'\x05\x00')
        ws.send(send_msg)
        gevent.sleep(2)
        recv = ws.receive()

        if recv != None:
            # print(recv)
            if recv[0] != 5 or recv[2] != 0:
                return False
        else:
            return False
        addr_type = recv[3]
        if addr_type == 1:
            addr = socket.inet_ntoa(recv[4:8])
        elif addr_type == 3:
            addr_len = recv[4]
            addr = socket.gethostbyname(recv[5:5 + addr_len])
        else:
            # only ipv4 addr or domain name is supported.
            return False

        port = recv[-2] * 256 + recv[-1]
        if recv[1] == 1:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            r = server_sock.connect_ex((addr,port))
            if r == 0:
                return server_sock
        else:
            return False
    except Exception as e:
        return False

@sockets.route('/echo')
def echo_socket(ws):
    app.total += 1
    server_sock = handshake(ws)
    if server_sock:
        sock_name = server_sock.getsockname()
        server_hex_addr = socket.inet_aton(sock_name[0])
        send_msg = b'\x05\x00\x00\x01' + server_hex_addr  + struct.pack(">H", sock_name[1])
        ws.send(send_msg)
        forwarders = (gevent.spawn(ws_remote, ws, server_sock),
                      gevent.spawn(local_ws, ws, server_sock))
        gevent.joinall(forwarders)
    else:
        try:
            send_msg = struct.pack("!BBBBIH", 5, 5, 0, 1, 0, 0)
            # print('not good')
            ws.send(send_msg)
            ws.close()
            app.total -= 1
            # print(F'total = {app.total}')
            return 
        except Exception as e:
            app.total -= 1
            # print(F'total = {app.total}')
            return

    ws.close()
    gc.collect()
    app.total -= 1
    # print(F'total = {app.total}')



from werkzeug.routing import BaseConverter
class RegexConverter(BaseConverter):
    def __init__(self, map, *args):
        self.map = map
        self.regex = args[0]
application.url_map.converters['regex'] = RegexConverter


# Filters.
# href=https://github.com/
href_out_re = re.compile(r'(href=)(https?)(:/)/')
# background: url(/static/logo.png)
url_re = re.compile(r'(url\()/')

#herf="/stati/xxx"
href_re = re.compile(r'((?:src|action|href)=["\'])/(?!/)')

#herf=\n"/static"
href_re_n = re.compile(r'((?:src|action|href)=\n["\'])/(?!/)',re.I |re.M)

#href="static/xx"
href_re2 = re.compile(r'((?:src|action|href)=["\'])(?!(//|/|https://|http://|\./|\.\./))')

#href="./static/xx"  didn't pass debug yet
href_re3 = re.compile(r'(((?:src|action|href)=["\'])\./)')

#href="../../static/xx"
href_re4 = re.compile(r'(((?:src|action|href)=["\\\'])(\\.\\./)+)')
#href="//xxx.x.x/abc"
myre = re.compile(r'((?:src|action|href)=["\'])//')

#href="https://abc.com/"
#myre2 = re.compile(r'(https?)://')
myre2 = re.compile(r'((?:src|action|href)=["\'])(https?)://')

#return afafa.aaf.afa hostname
host_re = re.compile(r'\w+([-.]\w+)*\.\w+([-.]\w+)*')

#return afaf.aaa.aa/aaad/aaa  /aaad/ directry
dir_re = re.compile(r'/(.*/)')

#replace handel 301,302
redirect_re = re.compile(r'://')

# @app.errorhandler(404)
# def not_found(error):
#     app.logger.debug(F'gogogo{request.headers}')
#     return redirect("/p/https/baidu.com")

def rstrip_path(url,n):
    #/abc/efg/ when n = 1 return /abc/ ,when n = 2 return /
    strip_path_re =  re.compile('[^/.]+/$')
    while n > 0:
        url = strip_path_re.sub('',url)
        n = n - 1
    return url

def getpath(url):
    #url = www.abc.com/  or www.abc.com or www.abc.com/abc or www.abc.com/abc/
    #should return /  /  /  /abc/

    path_re = re.compile('[^/]*(/.*/)')
    result = path_re.match(url)
    if result:
        return result[1]
    else:
        return '/'

def realpath(path,relative_path):
    num = relative_path.count('../')
    return rstrip_path(path,num)

@application.route('/')
def homepage():
    the_time = datetime.now().strftime("%A,%b %b %Y :%M")

    return """
    <meta http-equiv="Refresh" content="300" />
    <h1>Hello Friends form openshift 2020</h1>
    <p>It is currently {time}.</p>
    <img src="/1.jpg" />
    <p>lala</p>
    """.format(time=the_time)


@application.route('/1.jpg')
def getimage():
    image_binary = get("https://loremflickr.com/600/400").content
    response = make_response(image_binary)
    response.headers.set('Content-Type', 'image/jpeg')
 #   response.headers.set('Content-Disposition', 'attachment', filename='1.jpg')
    return response


@application.route('/p/<protocol>/<regex(".*"):url>',methods=['GET', 'POST'])
def hello(protocol,url):
    path = getpath(url)
    host = host_re.match(url)[0]
    root = F"/p/{protocol}/{host}"
    application.logger.debug(F"path = {path} :: host = {host} :: url = {url}")
    url = F"{protocol}://{url}"

    application.logger.debug(F"{protocol} :: {url} :: {request.args.to_dict()}")
    headers = {'Accept-Language' : request.headers['Accept-Language'],
               'User-Agent' : request.headers['User-Agent']}
    if request.method == 'GET':
        binary = get(url,params = request.args.to_dict(),headers = headers,allow_redirects=False)
    if request.method == 'POST':
        application.logger.debug(F"POST DADE={request.form.to_dict()}")
        binary = post(url,data = request.form.to_dict())
    if binary.status_code in [302,301]:

        return redirect('/p/'+redirect_re.sub('/',binary.headers['Location']))
    if 'text' in binary.headers['Content-Type']:
        changeurl = href_re.sub(F"\\1{root}/",binary.text)
        changeurl = href_re_n.sub(F"\\1{root}/",changeurl)
        changeurl = url_re.sub(F"\\1{root}/",changeurl)
        changeurl = href_re2.sub(F"\\1{url}",changeurl)
        changeurl = href_re3.sub(F"\\2{root}{path}",changeurl)
        changeurl = href_re4.sub("\\2" + realpath(path,'\\1'),changeurl)
        changeurl = myre.sub(F"\\1/p/{protocol}/",changeurl)
        changeurl = myre2.sub(F"\\1/p/\\2/",changeurl)
        changeurl = href_out_re.sub('\\1/p/\\2/',changeurl)
    else:
        changeurl = binary.content
    response = make_response(changeurl)
    
    # response.headers.clear()
    # for i in binary.headers:
    #     response.headers.add(i,binary.headers[i])
    # application.logger.debug(response.headers)
    response.headers.set('Content-Type',binary.headers['Content-Type'])
  #  response.headers.set('Content-Length',binary.headers['Content-Length'])
    return response


if __name__ == "__main__":
    application.run()
