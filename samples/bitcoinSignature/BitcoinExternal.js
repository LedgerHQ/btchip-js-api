/*
************************************************************************
Copyright (c) 2014 UBINITY SAS

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*************************************************************************
*/

var BitcoinExternal = Class.create({

	initialize: function() {

	},

	getSignedMessageHash: function(message) {
		var messageLength;
	    if (message.length < 0xfd) {
      		messageLength = new ByteString(Convert.toHexByte(message.length), HEX);
    	} else 
    	if (message.length <= 0xffff) {
      		messageLength = new ByteString("FD" + Convert.toHexByte(message.length & 0xff) + Convert.toHexByte((message.length >> 8) & 0xff), HEX);
      	}
      	else {
      		throw "Message too long";
      	}

		var sha = new JSUCrypt.hash.SHA256();		

		var messageToSign = new ByteString("18", HEX).concat(new ByteString("Bitcoin Signed Message:", ASCII)).concat(new ByteString("0A", HEX));
		messageToSign = messageToSign.concat(messageLength).concat(message);
		var result = sha.finalize(messageToSign.toString(HEX));
		result = new ByteString(JSUCrypt.utils.byteArrayToHexStr(result), HEX);
		result = sha.finalize(result.toString(HEX));
		result = new ByteString(JSUCrypt.utils.byteArrayToHexStr(result), HEX);

		return result;
	},

	splitAsn1Signature: function(asn1Signature) {
		if ((asn1Signature.byteAt(0) != 0x30) || (asn1Signature.byteAt(2) != 0x02)) {
			throw "Invalid signature format";
		}
		var rLength = asn1Signature.byteAt(3);
		if (asn1Signature.byteAt(4 + rLength) != 0x02) {
			throw "Invalid signature format";			
		}		
		var r = asn1Signature.bytes(4, rLength);
		var s = asn1Signature.bytes(4 + rLength + 2, asn1Signature.byteAt(4 + rLength + 1));
		if (r.length == 33) {
			r = r.bytes(1);
		}
		if (s.length == 33) {
			s = s.bytes(1);
		}
		if ((r.length != 32) || (s.length != 32)) {
			throw "Invalid signature format";			
		}
		return [ r, s ];
	},

	compressPublicKey: function(publicKey) {
		var compressedKeyIndex;
		var compressedKey;
		if (publicKey.byteAt(0) != 0x04) {
			return publicKey;
		}		
		if ((publicKey.byteAt(64) & 1) != 0) {
			compressedKeyIndex = 0x03;
		}
		else {
			compressedKeyIndex = 0x02;
		}
		var result = new ByteString(Convert.toHexByte(compressedKeyIndex), HEX).concat(publicKey.bytes(1, 32));
		return result;
	},

	recoverPublicKey: function(asn1Signature, digest, rec) {
		var splitSignature = this.splitAsn1Signature(asn1Signature);
		var recBN = new BigInteger("" + rec, 10);
		var BN2 = new BigInteger("2", 10);
		var BN4 = new BigInteger("4", 10);
		var domain = JSUCrypt.ECFp.getEcDomainByName("secp256k1");		
		var a = domain.curve.a;
		var b = domain.curve.b;
		var p = domain.curve.field;
		var G = domain.G;
		var order = domain.order;
		var r = new BigInteger(splitSignature[0].toString(HEX), 16);
		var s = new BigInteger(splitSignature[1].toString(HEX), 16);

    	var x = r.add(order.multiply(recBN.divide(BN2)));
	    var alpha = x.multiply(x).multiply(x).add(a.multiply(x)).add(b).mod(p);
    	var beta = alpha.modPow(p.add(BigInteger.ONE).divide(BN4), p);
    	var y = beta.subtract(recBN).isEven() ? beta : p.subtract(beta);
    	var R = new JSUCrypt.ECFp.AffinePoint(x, y, domain.curve);
    	var e = new BigInteger(digest.toString(HEX), 16);
    	var minus_e = e.negate().mod(order);
    	var inv_r = r.modInverse(order);
    	var Q = (R.multiply(s).add(G.multiply(minus_e))).multiply(inv_r);
		return new ByteString(JSUCrypt.utils.byteArrayToHexStr(Q.getUncompressedForm()), HEX);
	}

});


