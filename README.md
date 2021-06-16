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
