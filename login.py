# -*- coding: utf-8 -*-  
import requests
import base64  
import re  
import urllib
import rsa  
import json  
import binascii  
from bs4 import BeautifulSoup
  
class Userlogin:  
    def __init__(self):

        self.session = None
        self.homePage = None
        self.homePageText = None

    def userlogin(self,username,password,pagecount):  
        session = requests.Session()  
        url_prelogin = 'http://login.sina.com.cn/sso/prelogin.php?entry=weibo&callback=sinaSSOController.preloginCallBack&su=&rsakt=mod&client=ssologin.js(v1.4.5)&_=1364875106625'  
        url_login = 'http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.5)'  
  
        #get servertime,nonce, pubkey,rsakv  
        resp = session.get(url_prelogin)  
        print(resp.text)
        json_data = re.findall(r'(?<=\().*(?=\))', resp.text)[0]
        data      = json.loads(json_data)  


        servertime = data['servertime']  
        nonce      = data['nonce']  
        pubkey     = data['pubkey']  
        rsakv      = data['rsakv']  
  
        # calculate su  
        #print(urllib.parse.quote(username))
        su = base64.b64encode(username.encode(encoding="utf-8"))  
  
        #calculate sp  
        rsaPublickey = int(pubkey,16)  
        key = rsa.PublicKey(rsaPublickey,65537)  
        message = str(servertime) +'\t' + str(nonce) + '\n' + str(password)  
        sp = binascii.b2a_hex(rsa.encrypt(message.encode(encoding="utf-8"),key))  
        postdata = {  
                            'entry': 'weibo',  
                            'gateway': '1',  
                            'from': '',  
                            'savestate': '7',  
                            'userticket': '1',  
                            'ssosimplelogin': '1',  
                            'vsnf': '1',  
                            'vsnval': '',  
                            'su': su,  
                            'service': 'miniblog',  
                            'servertime': servertime,  
                            'nonce': nonce,  
                            'pwencode': 'rsa2',  
                            'sp': sp,  
                            'encoding': 'UTF-8',  
                            'url': 'http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',  
                            'returntype': 'META',  
                            'rsakv' : rsakv,  
                            }  
        resp = session.post(url_login, data=postdata)  
        self.session = session
        # # print resp.headers 
        #print(resp.content)
        login_url = re.findall(r'http://weibo.*&retcode=0',resp.text)   
        print(login_url)
        respo = session.get(login_url[0]) 

        uid = re.findall('"uniqueid":"(\d+)",',respo.text)[0]  
        url = "http://weibo.com/u/"+uid  
        respo = session.get(url)
        #print(respo.content)
        self.homePage = respo.content
        self.homePageText = respo.text

    def GET(self, url):
        return self.session.get(url)

    def POST(self, url, data):
        return self.session.post(url, data)

    def getFollows(self):
        #print(self.homePage)
        followUrl = re.findall(r'(\\/\\/weibo\.com\\/\d+\\/follow\?from=page_\d+&wvr=\d+&mod=headfollow#place)', self.homePage)[0]
        followUrl = "https:" + followUrl.replace('\\', "")
        respo = self.GET(followUrl)
        followPage = respo.content
        followList = re.findall(r'uid=\d+&nick=(.+?)\\', followPage)
        return followList

    def getFans(self):
        fansUrl = re.findall(r'(\\/\\/weibo\.com\\/\d+\\/fans\?from=\d+&wvr=\d+&mod=headfans&current=fans#place)', self.homePage)[0]
        fansUrl = "https:" + fansUrl.replace('\\', "")
        respo = self.GET(fansUrl)
        fansPage = respo.content
        fansList = re.findall(r'uid=\d+&nick=(.+?)\\', fansPage)
        print fansList
        return None

    def getHomePage(self):
        return self.homePage

if __name__ == '__main__':
    login = Userlogin()
    login.userlogin("", "", None)
    #login.getFollows()
    #print(login.getHomePage())
    login.getFans()