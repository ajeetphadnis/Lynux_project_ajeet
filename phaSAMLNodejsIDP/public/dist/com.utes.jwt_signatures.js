/**
 * http://usejsdoc.org/
 */
const asn1 = require('asn1.js');
const BN = require('bn.js');
const crypto = require('crypto');

const EcdsaDerSig = asn1.define('ECPrivateKey', function () {
					return this.seq().obj(
						this.key('r').int(),
						this.key('s').int()
					);
				});

				
		function asn1SigSigToConcatSig(asn1SigBuffer) {
			const rsSig = EcdsaDerSig.decode(asn1SigBuffer, 'der');
			return Buffer.concat([
				rsSig.r.toArrayLike(Buffer, 'be', 32),
				rsSig.s.toArrayLike(Buffer, 'be', 32)
			]);
		}

		function concatSigToAsn1SigSig(concatSigBuffer) {
			const r = new BN(concatSigBuffer.slice(0, 32).toString('hex'), 16, 'be');
			const s = new BN(concatSigBuffer.slice(32).toString('hex'), 16, 'be');
			return EcdsaDerSig.encode({ r, s }, 'der');
		}

		function ecdsaSign(hashBuffer, key) {
			const sign = crypto.createSign('sha256');
			sign.update(asBuffer(hashBuffer));
			const asn1SigBuffer = sign.sign(key, 'buffer');
			return asn1SigSigToConcatSig(asn1SigBuffer);
		}

		function ecdsaVerify(data, signature, key) {
			const verify = crypto.createVerify('SHA256');
			verify.update(data);
			const asn1sig = concatSigToAsn1Sig(signature);
			return verify.verify(key, new Buffer(asn1sig, 'hex'));
		}

		// Key: Buffer with key, Message: Buffer with message
		function hmacSha256(key, message) {
			// The algorithm requires the key to be of the same length as the
			// "block-size" of the hashing algorithm (SHA256 = 64-byte blocks).
			// Extension is performed by appending zeros.
			var fullLengthKey = extendOrTruncateKey(key);

			var outterKeyPad = 0x5c; // A constant defined by the spec.
			var innerKeyPad = 0x36; // Another constant defined by the spec.

			var outterKey = new Buffer(fullLengthKey.length);
			var innerKey = new Buffer(fullLengthKey.length);
			for(var i = 0; i < fullLengthKey.length; ++i) {
				outterKey[i] = outterKeyPad ^ fullLengthKey[i];
				innerKey[i] = innerKeyPad ^ fullLengthKey[i];
			}

			// sha256(outterKey + sha256(innerKey, message))
			// (Buffer.concat makes this harder to read)
			return sha256(Buffer.concat([outterKey, sha256(Buffer.concat([innerKey, message]))]));
		}


	module.exports = {
		asn1SigSigToConcatSig, 
		concatSigToAsn1SigSig,
		ecdsaSign,
		ecdsaVerify,
		hmacSha256,
	};