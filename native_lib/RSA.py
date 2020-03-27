import urllib.request, urllib.parse, http.client


class RSA_nodejs:

    @staticmethod
    def get_rsa_open_key_from_nodejs_server(key_phrase: str, key_len: int) -> dict:
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