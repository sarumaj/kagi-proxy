# kagi-proxy

Proxy service for [kagi.com](https://kagi.com).

I wrote a simple proxy service to share access to my kagi.com subscription with a limited number of people.

I use reversed proxy behind TLS, basic authentication scheme, CSRF and DDoS protection by employing request throttling.

An authenticated user gets redirected to my active kagi.com session.

Proxy is exposed behind [kagi.sarumaj.com](https://kagi.sarumaj.com):

<p align="center" width="100%">
    <a href="https://kagi.sarumaj.com" target="_blank">
        <img src="doc/image.png" alt="screenshot">
    </img></a>
</p>
