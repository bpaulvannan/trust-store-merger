Authentication using client SSL certificates is done using https://client.badssl.com
The client certificate can be downloaded from https://badssl.com/download/.
This server returns 200 OK if the correct client certificate is provided, and 400 Bad Request otherwise.

SSL Connection is tested using stackoverflow.com ssl certificate