## gopki

Create your own simple PKI!

### Why?

I've been using a light fork of https://github.com/Evolix/shellpki. (My version
is 94 lines tho). However [go1.15+ doesn't work out of the
box](https://golang.org/doc/go1.15#commonname) because (my?) shellpki doesn't
create Subject Alt Name (SAN). I didn't find how to do it with openssl(1) (who
doesn't love using this delightful software). Other software to create a PKI
are beasts (cloudflare/cfssl is like 50k without counting vendored lib).

I don't need all these 'enterprise' features so I wrote my own.

### Security concern / caveat

The key aren't encrypted since the only way to do it is [deprecated]
(https://github.com/golang/go/commit/57af9745bfad2c20ed6842878e373d6c5b79285a).
For this reason, the CA key isn't written to disk. The program outputs the key
to *stdout* so the user can save it in their favorite password manager. When
signing a new certificate, the CA's key will be required through a prompt.
