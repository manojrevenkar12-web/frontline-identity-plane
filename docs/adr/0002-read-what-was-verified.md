# 0002. Read what was verified

## Decision
The SAML verifier returns the element its signature covers and the consumer reads only that element, requiring
exactly one assertion. NameID is read whole and refused if it contains a comment. Keys and algorithms come from the
tenant's configuration, never from the message. JWT algorithms are fixed per issuer. DTDs are refused.

## Why
Signature wrapping, comment truncation, `alg: none`, HMAC keyed with a public key and keys shipped in the message all
come from verifying one thing and trusting another. The attack catalogue runs each of them; the ablation that reads
the first assertion lets wrapping in every time.
