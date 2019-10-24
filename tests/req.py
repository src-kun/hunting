import requests
import json

headers = {
'accept': '*/*',
'User-Agent' :'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv :71.0) Gecko/20100101 Firefox/71.0',
'Accept-Language' :'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
'Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8',
'X-Requested-With' :'XMLHttpRequest',
'Origin' :'http://msjbht.ddzz1.cn',
'Connection' :'keep-alive',
'Referer' :'http//msjbht.ddzz1.cn/user/index.html',
'Cookie' :'PHPSESSID=bgc94s7vdv9i6svvtm7ehkr63q',
'Pragma': 'no-cache'
}
print(headers)

offset = 0
limit = 10000

for i in range(1,22):
    data = 'sort=id&order=desc&offset=' + str(offset) + '&limit=10000&filter=%7B+%22channels_code%22%3A+%22-1%22%2C+%22state%22%3A+%22-1%22%2C+%22is_vip%22%3A+%22-1%22%2C+%22is_login%22%3A+%22-1%22%2C+%22device%22%3A+%22-1%22%2C+%22zy_black%22%3A+%22-1%22+%7D'
    rep = requests.post(url= 'http://msjbht.ddzz1.cn/user/index.html',data=data, headers=headers)
    print(json.dumps(rep.json()))
    print(offset)
    offset = i*limit