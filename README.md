
Get the directions (ip) to a domain

    resp = directions.to('google.com')


Reponse with status code `NoError` is a successful request

    <Response [NoError]>

## Response object

Get response dns packet

    resp.dns_packet # => dictionary of values

Get ip

    resp.ip