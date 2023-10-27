/*
MIT License

Author Alexander Sasha Semenov

Copyright (c) 2023 TUM Blockchain Club

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
module verificator::verificator {

  use sui::ed25519;

  public entry fun verify_sig(pk: vector<u8>, sig: vector<u8>, msg: vector<u8>): bool {
    let isvalid: bool = ed25519::ed25519_verify(&sig, &pk, &msg);
    isvalid
   }
  
  #[test]
  fun test_verify_sig() {
    let msg: vector<u8> = x"181D402C293144636EE8A0E74F37FA3F565A5BAA8FE5A202DC66D28628CA084962D4911E6FBDCBF9BD8B7EB05325CFBE1CCBC9E871F71361488F145707123B07";
    let pk: vector<u8> = x"29528A5A7DE916DB8AE7A5854373B2ED3E47993F3AD49A75B7DF21136AEBE0BB";
    let sig: vector<u8> = x"AA2DD8AA6082F270ECF0FDF478283A73FE09A13B2F8960B9548CA9252542F0EE1B459AB17431CDDCFCB973560BC8AA9D738DBF2E889B61833C579109C83BA808";
    let verify: bool = ed25519::ed25519_verify(&sig, &pk, &msg);
    assert!(verify, 0);
  }
}