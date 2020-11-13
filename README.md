![JWS-CT](https://cyberphone.github.io/doc/security/jws-ct.svg)

## JWS/CT - Combining "Detached" JWS with JCS (JSON Canonicalization Scheme)
This repository contains a PoC showing how you can create "clear text" JSON signatures
by combining detached JWS compact objects with a simple
[canonicalization](https://github.com/cyberphone/json-canonicalization#json-canonicalization)
scheme.

### Problem Statement
Assume you have a JSON object like the following:
```json
{
  "statement": "Hello signed world!",
  "otherProperties": [2e+3, true]
}
```
If you would like to sign this object using JWS compact mode you would end-up with something like this:
```code
eyJhbGciOiJIUzI1NiIsImtpZCI6Im15a2V5In0.eyJvdGhlclByb3BlcnRpZXMiOlsyMDAwLHRydWVdLCJzdG
F0ZW1lbnQiOiJIZWxsbyBzaWduZWQgd29ybGQhIn0.FcE8h0GXJaOZ4Th3fNDBgcBE5HfEplOnS8GGtoSLU1K
```
That's not very cool since one of the major benefits of text based schemes (*human readability*), got lost in the process.
In addition, *the whole JSON structure was transformed into something entirely different*. 
### Clear Text Signatures
By rather using JWS in "detached" mode you can reap the benefits of text based schemes while
keeping existing security standards!  
```json
{
  "statement": "Hello signed world!",
  "otherProperties": [2e+3, true],
  "signature": "eyJhbGciOiJIUzI1NiIsImtpZCI6Im15a2V5In0..5HfEplOnS8GGtoSLU1KFcE8h0GXJaOZ4Th3fNDBgcBE"
}
```
You may wonder why this is not already described in the JWS standard, right?  Since JSON doesn't require
object properties to be in any specific order as well as having multiple ways of representing the same data, 
you must apply a *filter process* to the original object in order to create a *unique and platform 
independent representation* of the JWS "payload".  Applied to the sample you would get:
```json
{"otherProperties":[2000,true],"statement":"Hello signed world!"}
```
Note that this method is *internal to the signatures process*. The "wire format" can be kept "as is" although the
canonicalized version of the object would also be fully valid.

The knowledgeable reader probably realizes that this is quite similar to using an HTTP header for holding a detached JWS object.
The primary advantages of this scheme versus using HTTP headers include:
- Due to *transport independence*, signed objects can for example be used in
browsers expressed in JavaScript or be asynchronously exchanged over WebSockets
- Signed objects can be *stored in databases* without losing the signature
- Signed objects can be *embedded in other JSON objects* since they conform to JSON

### On Line Demo
If you want to test the signature scheme without any installation or downloading, a
demo is currently available at: https://mobilepki.org/jws-ct/home

### Detailed Signing Operation
1. Create or parse the JSON object to be signed
2. Use the result of the previous step as input to the canonicalizing
process described in
 https://tools.ietf.org/html/rfc8785#section-3.2
3. Use the result of the previous step as "JWS Payload" to the JWS signature process described in
https://tools.ietf.org/html/rfc7515#appendix-F using the *compact* serialization mode
4. Add the resulting JWS string to the original JSON
object through a *designated signature property of your choice*

### Detailed Validation Operation
1. Parse the signed JSON object
2. Read and save the JWS string from the *designated signature property*
3. Remove the *designated signature property* from the parsed JSON object
4. Apply the canonicalizing process described in
 https://tools.ietf.org/html/rfc8785#section-3.2 on the remaining object
5. Use the result of the previous step as "JWS Payload" to the JWS validation process described in
https://tools.ietf.org/html/rfc7515#appendix-F

### Available Canonicalization Software
- https://www.npmjs.com/package/canonicalize
- https://github.com/cyberphone/json-canonicalization/tree/master/dotnet#json-canonicalizer-for-net
- https://github.com/cyberphone/json-canonicalization/tree/master/java/canonicalizer#json-canonicalizer-for-java
