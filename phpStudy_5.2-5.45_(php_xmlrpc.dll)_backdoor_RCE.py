import requests
def test_post_http(ip):
    try:
        url = 'http://' + ip
        headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
		'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
		'accept-charset': 'c3lzdGVtKCdjYWxjLmV4ZScpOw==',
		'Accept-Encoding': 'gzip,deflate',
		'Accept-Language': 'en-US,en;q=0.5',
        } 
        r = requests.post(url, headers=headers)
    	print r.text
    except Exception as e:
            print '[!]Error:%s'%e
if __name__ == '__main__':
    file_object = open('ip.txt', 'r')
    for line in file_object:
        test_post_http(line.strip('\r\n'))



