import urllib.request, urllib.parse, http.client


class RSA_nodejs:

    @staticmethod
    def get_rsa_open_key_from_nodejs_server(key_phrase: str, key_len: int) -> bytes:
        params = urllib.parse.urlencode(
            {
                'key_phrase': key_phrase,
                'key_len': key_len,
            }
        )
        conn = http.client.HTTPConnection("127.0.0.1:3000")
        headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
        conn.request('POST', '/rsa_generate_open_key', params, headers)
        response = conn.getresponse()
        return response.read()

    @staticmethod
    def get_rsa_encryption_from_nodejs_server(open_rsa_key: str, key_md5: str, data: str) -> bytes:
        params = urllib.parse.urlencode(
            {
                'open_rsa_key': open_rsa_key,
                'key_md5': key_md5,
                'data': data,
            }
        )
        conn = http.client.HTTPConnection("127.0.0.1:3000")
        headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
        conn.request('POST', '/rsa_encryption', params, headers)
        response = conn.getresponse()
        return response.read()