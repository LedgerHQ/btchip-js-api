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

require('Card');

var BTChip = Class.create({
	
	/**
	 * @class Communication with Bitcoin application over a {@link Card} 
	 * @param {Object} @Card implementing the Bitcoin application
	 * @constructs
	 */
	initialize : function(card) {
		if (!(card instanceof Card)) {
			throw "Invalid card";
		}
		this.card = card;
		this.deprecatedFirmwareVersion = false;
	},

	setCompressedPublicKeys : function(compressedPublicKeys) {
		this.compressedPublicKeys = compressedPublicKeys;
	},

	setDeprecatedFirmwareVersion : function() {
		this.deprecatedFirmwareVersion = true;
	},

	_almostConvertU32 : function(number) {
		if (number instanceof ByteString) {
			return number;
		}
		return new ByteString(Convert.toHexByte((number >> 24) & 0xff) + Convert.toHexByte((number >> 16) & 0xff) + Convert.toHexByte((number >> 8) & 0xff) + Convert.toHexByte(number & 0xff), HEX);
	},

	setupNew_async: function(modeMask, featuresMask, version, versionP2sh, pin, wipePin, keymapEncoding, restoreSeed, bip32SeedOrEntropy, wrappingKey) {
		if (typeof modeMask == "undefined") {
			modeMask = BTChip.MODE_WALLET;
		}
		if (typeof featuresMask == "undefined") {
			featuresMask = 0x00;
		}
		if (typeof pin == "undefined") {
			pin = new ByteString("00000000", ASCII);
		}
		if (typeof keymapEncoding == "undefined") {
			keymapEncoding = BTChip.QWERTY_KEYMAP_NEW;
		}
		var data = Convert.toHexByte(modeMask);
		data += Convert.toHexByte(featuresMask);
		data += Convert.toHexByte(version);
		data += Convert.toHexByte(versionP2sh);
		data += Convert.toHexByte(pin.length) + pin.toString(HEX);
		if (typeof wipePin == "undefined") {
			data += "00";
		}
		else {
			data += Convert.toHexByte(wipePin.length) + wipePin.toString(HEX);
		}
		data += keymapEncoding.toString(HEX);
		data += Convert.toHexByte(restoreSeed ? 0x01 : 0x00);
		if (typeof bip32SeedOrEntropy == "undefined") {
			for (var i=0; i<32; i++) {	
				data += "00";
			}
		}
		else {
			if (bip32SeedOrEntropy.length != 32) {
				throw "Invalid seed length";
			}
			data += bip32SeedOrEntropy.toString(HEX);
		}
		if (typeof wrappingKey == "undefined") {
			data += "00";
		}
		else {
			data += Convert.toHexByte(wrappingKey.length) + wrappingKey.toString(HEX);
		}

		return this.card.sendApdu_async(0xe0, 0x20, 0x00, 0x00, new ByteString(data, HEX), [0x9000]).then(function(result) {
                  var offset = 1;
                  var resultList = {};
				  resultList['trustedInputKey'] = result.bytes(offset, 16);
				  offset += 16;
				  resultList['keyWrappingKey'] = result.bytes(offset, 16);
				  return resultList;
        });
	},	

	setup_async: function(modeMask, version, versionP2sh, pin, wipePin, keymapEncodings, restoreSeed, bip32SeedOrEntropy, wrappingKey) {
		if (typeof modeMask == "undefined") {
			modeMask = 0x01;
		}
		if (typeof pin == "undefined") {
			pin = new ByteString("00000000", ASCII);
		}
		if (typeof keymapEncodings == "undefined") {
			keymapEncodings = [ BTChip.QWERTY_KEYMAP ];
		}
		var data = Convert.toHexByte(modeMask);
		data += Convert.toHexByte(version);
		data += Convert.toHexByte(versionP2sh);
		data += Convert.toHexByte(pin.length) + pin.toString(HEX);
		if (typeof wipePin == "undefined") {
			data += "00";
		}
		else {
			data += Convert.toHexByte(wipePin.length) + wipePin.toString(HEX);
		}
		data += Convert.toHexByte(keymapEncodings.length);
		for (var i=0; i<keymapEncodings.length; i++) {
			data += keymapEncodings[i].toString(HEX);
		}
		data += Convert.toHexByte(restoreSeed ? 0x01 : 0x00);
		if (typeof bip32SeedOrEntropy == "undefined") {
			for (var i=0; i<32; i++) {	
				data += "00";
			}
		}
		else {
			if (bip32SeedOrEntropy.length != 32) {
				throw "Invalid seed length";
			}
			data += bip32SeedOrEntropy.toString(HEX);
		}
		if (typeof wrappingKey == "undefined") {
			data += "00";
		}
		else {
			data += Convert.toHexByte(wrappingKey.length) + wrappingKey.toString(HEX);
		}
		//alert(data);
		return this.card.sendApdu_async(0xe0, 0x20, 0x00, 0x00, new ByteString(data, HEX), [0x9000]).then(function(result) {
                  var offset = 0;
                  var resultList = {};
		  resultList['random'] = result.bytes(offset, 32);
		  offset += 32;
                  resultList['bip32seed'] = result.bytes(offset, 32);
                  offset += 32;
                  resultList['hotpKey'] = result.bytes(offset, 48);
                  offset += 48;
                  resultList['trustedInputKey'] = result.bytes(offset, 16);
                  offset += 16;
                  resultList['keyWrappingKey'] = result.bytes(offset, 16);
                  return resultList;
                });
	},

	verifyPin_async : function(pin) {
		return this.card.sendApdu_async(0xe0, 0x22, 0x00, 0x00, pin, [0x9000]);
	},

	getOperationMode_async : function() {
		return this.card.sendApdu_async(0xe0, 0x24, 0x00, 0x00, 0x01, [0x9000]).then (function (result) {
                  return result.byteAt(0);
                });
	},

	setOperationMode_async : function(operationMode) {
		return this.card.sendApdu_async(0xe0, 0x26, 0x00, 0x00, new ByteString(Convert.toHexByte(operationMode), HEX), [0x9000]);
	},

	getFirmwareVersion_async : function() {
		return this.card.sendApdu_async(0xe0, 0xc4, 0x00, 0x00, 0x04, [0x9000]).then(function(result) {
				var response = {};
				response['compressedPublicKeys'] = (result.byteAt(0) == 0x01);
				response['firmwareVersion'] = result.bytes(1);
				return response;
		});
	},

	getWalletPublicKey_async : function(account, chainIndex, internalChain) {
		if (typeof account == "undefined") {
			account = 0;
		}
		var data = this._almostConvertU32(account).concat(this._almostConvertU32(chainIndex));
		return this.card.sendApdu_async(0xe0, 0x40, (internalChain ? BTChip.INTERNAL_CHAIN : BTChip.EXTERNAL_CHAIN), 0x00, data, [0x9000]).then(function (result) {
                  var resultList = {};
                  var offset = 0;
                  resultList['publicKey'] = result.bytes(offset + 1, result.byteAt(offset));
                  offset += result.byteAt(offset) + 1;
                  resultList['bitcoinAddress'] = result.bytes(offset + 1, result.byteAt(offset));
                  return resultList;
                });
	},

	signMessagePrepare_async : function(account, chainIndex, internalChain, message) {
		var data = this._almostConvertU32(account).concat(this._almostConvertU32(chainIndex));
		data = data.concat(new ByteString(Convert.toHexByte((internalChain ? BTChip.INTERNAL_CHAIN : BTChip.EXTERNAL_CHAIN)), HEX));
		data = data.concat(new ByteString(Convert.toHexByte(message.length), HEX));
		data = data.concat(message);
		return this.card.sendApdu_async(0xe0, 0x4e, 0x00, 0x00, data);
	},

	signMessageSign_async : function(pin) {
		var data;
		if (typeof pin != "undefined") {
			data = pin;
		}
		else {
			data = new ByteString("", HEX);
		}
		return this.card.sendApdu_async(0xe0, 0x4e, 0x80, 0x00, data);
	},

	ecdsaSignImmediate_async : function(privateKeyEncryptionVersion, encryptedPrivateKey, hash) {
		var data = "";
		data = data + Convert.toHexByte(privateKeyEncryptionVersion);
		data = data + Convert.toHexByte(encryptedPrivateKey.length);
		data = new ByteString(data, HEX);
		data = data.concat(encryptedPrivateKey);
		data = data.concat(hash);
		return this.card.sendApdu_async(0xe0, 0x40, 0x00, 0x00, data, [0x9000]);
	},

	ecdsaVerifyImmediate_async : function(publicKey, hash, signature, curveFid) {
		if (typeof curveFid == 'undefined') {
			curveFid = 0xb1c0;
		}
		var data = new ByteString(Convert.toHexShort(curveFid) + Convert.toHexByte(publicKey.length), HEX);
		data = data.concat(publicKey);
		data = data.concat(new ByteString(Convert.toHexByte(hash.length), HEX));
		data = data.concat(hash);
		data = data.concat(signature);
		return this.card.sendApdu_async(0xe0, 0x40, 0x80, 0x00, data, [0x9000]);		
	},

	getTrustedInputRaw_async: function(firstRound, indexLookup, transactionData) {
		var data = "";
		if (firstRound) {
			data = data + Convert.toHexByte((indexLookup >> 24) & 0xff) + Convert.toHexByte((indexLookup >> 16) & 0xff) + Convert.toHexByte((indexLookup >> 8) & 0xff) + Convert.toHexByte(indexLookup & 0xff);
			data = new ByteString(data, HEX).concat(transactionData);
		}
		else {
			data = transactionData;
		}
		return this.card.sendApdu_async(0xe0, 0x42, (firstRound ? 0x00 : 0x80), 0x00, data, [0x9000]);
	},

	getTrustedInput_async: function(indexLookup, transaction) {
          var currentObject = this;
          var deferred = Q.defer();
          var data = transaction['version'].concat(currentObject.createVarint(transaction['inputs'].length));
          currentObject.getTrustedInputRaw_async(true, indexLookup, data).then(function (result) {
            async.eachSeries(
              transaction['inputs'], 
              function (input, finishedCallback) {
                data = input['prevout'].concat(currentObject.createVarint(input['script'].length));
                data = data.concat(input['script']).concat(input['sequence']);
                currentObject.getTrustedInputRaw_async(false, undefined, data).then(function (result) {
                  // iteration (eachSeries) ended
                  // TODO notify progress
                  // deferred.notify("input");
                  finishedCallback();
                }).fail(function (err) { deferred.reject(err); });
              },
              function(finished) {
                data = currentObject.createVarint(transaction['outputs'].length);
                currentObject.getTrustedInputRaw_async(false, undefined, data).then(function (result) {
                  async.eachSeries(
                    transaction['outputs'],
                    function(output, finishedCallback) {
                          data = output['amount'];
                          data = data.concat(currentObject.createVarint(output['script'].length).concat(output['script']));
                          currentObject.getTrustedInputRaw_async(false, undefined, data).then(function(result) {
                            // iteration (eachSeries) ended
                            // TODO notify progress
                            // deferred.notify("output");
                            finishedCallback();
                          }).fail(function (err) { deferred.reject(err); });
                    },
                    function(finished) {
                      data = transaction['locktime'];
                      currentObject.getTrustedInputRaw_async(false, undefined, data).then (function(result) {
                        deferred.resolve(result);
                      }).fail(function (err) { deferred.reject(err); });
                    }
                  );
                }).fail(function (err) { deferred.reject(err); });
              }
            );
          }).fail(function (err) { deferred.reject(err); });
          // return the promise to be resolve when the trusted input has been processed completely
          return deferred.promise;
	},

	startUntrustedHashTransactionInputRaw_async: function(newTransaction, firstRound, transactionData) {
		return this.card.sendApdu_async(0xe0, 0x44, (firstRound ? 0x00 : 0x80), (newTransaction ? 0x00 : 0x80), transactionData, [0x9000]);
	},

	startUntrustedHashTransactionInput_async: function(newTransaction, transaction, trustedInputs) {
                var currentObject = this;
		var data = transaction['version'].concat(currentObject.createVarint(transaction['inputs'].length));
                var deferred = Q.defer();
		currentObject.startUntrustedHashTransactionInputRaw_async(newTransaction, true, data).then(function (result) {
				  var i = 0;
                  async.eachSeries(
                    transaction['inputs'],
                    function (input, finishedCallback) {
                        var inputKey;
                        data = new ByteString(Convert.toHexByte(0x01) + Convert.toHexByte(trustedInputs[i].length), HEX);
                        data = data.concat(trustedInputs[i]).concat(currentObject.createVarint(input['script'].length));
                        currentObject.startUntrustedHashTransactionInputRaw_async(newTransaction, false, data).then(function(result) {
                          data = input['script'].concat(input['sequence']);
                          currentObject.startUntrustedHashTransactionInputRaw_async(newTransaction, false, data).then(function (result) {
                            // TODO notify progress
                            i++;
                            finishedCallback();                            
                          }).fail(function (err) { deferred.reject(err); });
                        }).fail(function (err) { deferred.reject(err); });
                    },
                    function (finished) {
                      deferred.resolve(finished);
                    }
                  )
                }).fail(function (err) { deferred.reject(err); });
                // return the notified object at end of the loop
                return deferred.promise;
	},

	hashOutputInternal_async: function(outputType, account, chainIndex, internalChain, outputAddress, amount, fees) {
		if (typeof changeKey == "undefined") {
			changeKey = new ByteString("", HEX);
		}
		var data = new ByteString(Convert.toHexByte(outputAddress.length), HEX);
		data = data.concat(outputAddress);
		data = data.concat(amount).concat(fees);
		data = data.concat(this._almostConvertU32(account).concat(this._almostConvertU32(chainIndex)));
		var p2;
		if (this.deprecatedFirmwareVersion) {
			p2 = 0x00;
		}
		else {
			p2 = (internalChain ? BTChip.INTERNAL_CHAIN : BTChip.EXTERNAL_CHAIN);
		}
		return this.card.sendApdu_async(0xe0, 0x46, outputType, p2, data, [0x9000]).then(function (outData) {
                  var result = {};
                  var scriptDataLength = outData.byteAt(0);
                  result['scriptData'] = outData.bytes(1, scriptDataLength);
                  result['authorizationRequired'] = (outData.byteAt(1 + scriptDataLength) == 0x01);
                  return result;
                });
	}, 

	hashOutputBinary_async: function(account, chainIndex, internalChain, outputAddress, amount, fees) {
		return this.hashOutputInternal_async(0x01, account, chainIndex, internalChain, outputAddress, amount, fees);
	},

	hashOutputBase58_async: function(account, chainIndex, internalChain, outputAddress, amount, fees) {
		return this.hashOutputInternal_async(0x02, account, chainIndex, internalChain, outputAddress, amount, fees);
	},

	signTransaction_async: function(account, chainIndex, internalChain, transactionAuthorization, lockTime, sigHashType) {
		if (typeof transactionAuthorization == "undefined") {
			transactionAuthorization = new ByteString("", HEX);
		}
		if (typeof lockTime == "undefined") {
			lockTime = BTChip.DEFAULT_LOCKTIME;
		}
		if (typeof sigHashType == "undefined") {
			sigHashType = BTChip.SIGHASH_ALL;
		}
		var data = this._almostConvertU32(account).concat(this._almostConvertU32(chainIndex));
		if (internalChain) {
			data = data.concat(new ByteString(Convert.toHexByte(BTChip.INTERNAL_CHAIN), HEX));
		}
		else {
			data = data.concat(new ByteString(Convert.toHexByte(BTChip.EXTERNAL_CHAIN), HEX));
		}
		data = data.concat(new ByteString(Convert.toHexByte(transactionAuthorization.length), HEX));
		data = data.concat(transactionAuthorization);
		data = data.concat(lockTime);
		data = data.concat(new ByteString(Convert.toHexByte(sigHashType), HEX));
		return this.card.sendApdu_async(0xe0, 0x48, 0x00, 0x00, data, [0x9000]);
	},

	createInputScript: function(publicKey, signatureWithHashtype) {
		var data = new ByteString(Convert.toHexByte(signatureWithHashtype.length), HEX).concat(signatureWithHashtype);	
		data = data.concat(new ByteString(Convert.toHexByte(publicKey.length), HEX)).concat(publicKey);
		return data;
	},

	compressPublicKey: function(publicKey) {
		var prefix = ((publicKey.byteAt(64) & 1) != 0 ? 0x03 : 0x02);
		return new ByteString(Convert.toHexByte(prefix), HEX).concat(publicKey.bytes(1, 32));
	},

	createPaymentTransaction_async: function(inputs, associatedKeysets, changeAccount, changeIndex, changeInternalChain, outputAddress, amount, fees, lockTime, sighashType, authorization, resumeData) {
		// Inputs are provided as arrays of [transaction, output_index]
		// associatedKeysets are provided as arrays of [account, chainIndex, internalChain]
		var defaultVersion = new ByteString("01000000", HEX);
		var defaultSequence = new ByteString("FFFFFFFF", HEX);
		var trustedInputs = [];
		var regularOutputs = [];
		var signatures = [];
		var firstRun = true;
		var scriptData;
		var resuming = (typeof authorization != "undefined");
        var currentObject = this;
		
		if (typeof lockTime == "undefined") {
                  lockTime = BTChip.DEFAULT_LOCKTIME;
		}
		if (typeof sigHashType == "undefined") {
                  sigHashType = BTChip.SIGHASH_ALL;
		}

		var deferred = Q.defer();

		async.eachSeries(
                  inputs,
                  function(input, finishedCallback) {
                    if (!resuming) {
                      currentObject.getTrustedInput_async(input[1], input[0]).then(function(result) {
                        trustedInputs.push(result);
                        regularOutputs.push(input[0].outputs[input[1]]);
                        finishedCallback();
                      }).fail(function(err){deferred.reject(err);});
                    }
                    else {
                      regularOutputs.push(input[0].outputs[input[1]]);
                      finishedCallback();
                    }
                  },
                  function(finished) {
                    if (resuming) {
                      trustedInputs = resumeData['trustedInputs'];
                      firstRun = false;
                    }
                    // Pre-build the target transaction
                    var targetTransaction = {};
                    targetTransaction['version'] = defaultVersion;
                    targetTransaction['inputs'] = [];
                    for (var i=0; i<inputs.length; i++) {
                      var tmpInput = {};
                      tmpInput['script'] = new ByteString("", HEX);
                      tmpInput['sequence'] = defaultSequence;
                      targetTransaction['inputs'].push(tmpInput);
                    }
                    
                    // compute public keys
                    var deferredPublicKeys = Q.defer();

                    // process public keys
                    deferredPublicKeys.promise.then(function (publicKeys) {
                      // Sign each input 
                      var i=0;
                      async.eachSeries(
                        inputs,
                        function (input, finishedCallback) {
                          targetTransaction['inputs'][i]['script'] = regularOutputs[i]['script'];			
                          var resultHash;			
                          currentObject.startUntrustedHashTransactionInput_async(firstRun, targetTransaction, trustedInputs).then(function(result) {;
                            currentObject.hashOutputBase58_async(changeAccount, changeIndex, changeInternalChain, outputAddress, amount, fees).then(function (resultHash) {
                              if (resultHash['scriptData'].length != 0) {
                                      scriptData = resultHash['scriptData'];
                              }
                              if (resultHash['authorizationRequired']) { 
                                      // we're in the resume phase, but still required for authorization, this is odd
                                      if (resuming) {
                                        deferred.reject("Authorization has been rejected");
                                        return;
                                      }
                                
                                      var resumeData = {};
                                      resumeData['authorizationRequired'] = resultHash['authorizationRequired'];
                                      resumeData['scriptData'] = scriptData;
                                      resumeData['trustedInputs'] = trustedInputs;
                                      resumeData['publicKeys'] = publicKeys;
                                      // return current state
                                      deferred.resolve(resumeData);
                              }
                              currentObject.signTransaction_async(associatedKeysets[i][0], associatedKeysets[i][1], associatedKeysets[i][2], authorization, lockTime, sigHashType).then(function(result) {
                                signatures.push(result);
                                targetTransaction['inputs'][i]['script'] = new ByteString("", HEX);			
                                if (firstRun) {
                                        firstRun = false;
                                }
                                // finished with this iteration
                                i++;
                                finishedCallback();
                              }).fail(function(err){deferred.reject(err);});
                            }).fail(function(err){deferred.reject(err);});
                          }).fail(function(err){deferred.reject(err);});
                        },
                        function (finished) {
                          // Populate the final input scripts
                          var i=0;
                          async.eachSeries(
                            inputs,
                            function(input, finishedCallback) {
                              var tmpScriptData = new ByteString(Convert.toHexByte(signatures[i].length), HEX);
                              tmpScriptData = tmpScriptData.concat(signatures[i]);
                              tmpScriptData = tmpScriptData.concat(new ByteString(Convert.toHexByte(publicKeys[i].length), HEX));
                              tmpScriptData = tmpScriptData.concat(publicKeys[i]);
                              targetTransaction['inputs'][i]['script'] = tmpScriptData;
                              targetTransaction['inputs'][i]['prevout'] = trustedInputs[i].bytes(4, 0x24);
                              // prepare next iteration
                              i++;
                              finishedCallback();
                            },
                            function(finished) {
                              var result = currentObject.serializeTransaction(targetTransaction);
                              result = result.concat(scriptData);
                              result = result.concat(currentObject.reverseBytestring(lockTime));
                              // return result
                              deferred.resolve(result);
                            }
                          );
                        }
                      );
                    });
                    
                    // compute public keys, then continue signing
                    if (!resuming) {
                      var publicKeysArray = [];
                      var i=0;
                      async.eachSeries(
                        inputs,
                        function(input, finishedCallback) {
                          currentObject.getWalletPublicKey_async(associatedKeysets[i][0], associatedKeysets[i][1], associatedKeysets[i][2]).then(function(result) {
							if (currentObject.compressedPublicKeys) {                          	
	                            publicKeysArray[i] = currentObject.compressPublicKey(result['publicKey']);
	                        }
	                        else {
								publicKeysArray[i] = result['publicKey'];
	                        }
                            // prepare next iteration
                            i++;
                            finishedCallback();
                          }).fail(function(err){deferred.reject(err);});
                        },
                        function(finished) {
                          // we've computed all public keys
                          deferredPublicKeys.resolve(publicKeysArray);
                        }
                      );
                    }
                    else {
                      // this is resuming, reuse already computed during first pass
                      deferredPublicKeys.resolve(resumeData['publicKeys']);
                    }
                  }
                );
                return deferred.promise;
	},

	serializeTransaction: function(transaction) {
		var data = transaction['version'].concat(this.createVarint(transaction['inputs'].length));
		for (var i=0; i<transaction['inputs'].length; i++) {
			var input = transaction['inputs'][i];
			data = data.concat(input['prevout'].concat(this.createVarint(input['script'].length)));
			data = data.concat(input['script']).concat(input['sequence']);
		}
		if (typeof transaction['outputs'] != "undefined") {
			data = data.concat(this.createVarint(transaction['outputs'].length));
			for (var i=0; i<transaction['outputs'].length; i++) {
				var output = transaction['outputs'][i];
				data = data.concat(output['amount']);
				data = data.concat(this.createVarint(output['script'].length).concat(output['script']));
			}
			data = data.concat(transaction['locktime']);
		}
		return data;
	},

	getVarint : function(data, offset) {
		if (data.byteAt(offset) < 0xfd) {
			return [ data.byteAt(offset), 1 ];
		}
		if (data.byteAt(offset) == 0xfd) {
			return [ ((data.byteAt(offset + 2) << 8) + data.byteAt(offset + 1)), 3 ];
		}
		if (data.byteAt(offset) == 0xfe) {
			return [ ((data.byteAt(offset + 4) << 24) + (data.byteAt(offset + 3) << 16) + 
				  (data.byteAt(offset + 2) << 8) + data.byteAt(offset + 1)), 5 ];
		}
	},

	reverseBytestring : function(value) {
		var result = "";
		for (var i=0; i<value.length; i++) {
			result = result + Convert.toHexByte(value.byteAt(value.length - 1 - i));
		}
		return new ByteString(result, HEX);
	},

	createVarint : function(value) {
		if (value < 0xfd) {
			return new ByteString(Convert.toHexByte(value), HEX);
		}
		if (value <= 0xffff) {
			return new ByteString("fd" + Convert.toHexByte(value & 0xff) + Convert.toHexByte((value >> 8) & 0xff), HEX);
		}
		return new ByteString("fe" + Convert.toHexByte(value & 0xff) + Convert.toHexByte((value >> 8) & 0xff) + Convert.toHexByte((value >> 16) & 0xff) + Convert.toHexByte((value >> 24) & 0xff));
	},

	splitTransaction: function(transaction) {
		var result = {};
		var inputs = [];
		var outputs = [];
		var offset = 0;
		var version = transaction.bytes(offset, 4);
		offset += 4;
		var varint = this.getVarint(transaction, offset);
		var numberInputs = varint[0];
		offset += varint[1];
		for (var i=0; i<numberInputs; i++) {
			var input = {};
			input['prevout'] = transaction.bytes(offset, 36);
			offset += 36;
			varint = this.getVarint(transaction, offset);
			offset += varint[1];
			input['script'] = transaction.bytes(offset, varint[0]);
			offset += varint[0];
			input['sequence'] = transaction.bytes(offset, 4);
			offset += 4;
			inputs.push(input);
		}		
		varint = this.getVarint(transaction, offset);
		var numberOutputs = varint[0];
		offset += varint[1];
		for (var i=0; i<numberOutputs; i++) {
			var output = {};
			output['amount'] = transaction.bytes(offset, 8);
			offset += 8;
			varint = this.getVarint(transaction, offset);
			offset += varint[1];
			output['script'] = transaction.bytes(offset, varint[0]);
			offset += varint[0];
			outputs.push(output);
		}
		var locktime = transaction.bytes(offset, 4);
		result['version'] = version;
		result['inputs'] = inputs;
		result['outputs'] = outputs;
		result['locktime'] = locktime;
		return result;
	},

	displayTransactionDebug: function(transaction) {
		alert("version " + transaction['version'].toString(HEX));
		for (var i=0; i<transaction['inputs'].length; i++) {
			var input = transaction['inputs'][i];
			alert("input " + i + " prevout " + input['prevout'].toString(HEX) + " script " + input['script'].toString(HEX) + " sequence " + input['sequence'].toString(HEX)); 
		}
		for (var i=0; i<transaction['outputs'].length; i++) {
			var output = transaction['outputs'][i];
			alert("output " + i + " amount " + output['amount'].toString(HEX) + " script " + output['script'].toString(HEX));
		}
		alert("locktime " + transaction['locktime'].toString(HEX));
	},

});

BTChip.MODE_WALLET = 0x01;
BTChip.MODE_RELAXED_WALLET = 0x02;
BTChip.MODE_SERVER = 0x04;
BTChip.MODE_DEVELOPER = 0x08;
BTChip.FLAG_RFC6979 = 0x80;

BTChip.FEATURE_UNCOMPRESSED_KEYS = 0x01;
BTChip.FEATURE_DETERMINISTIC_SIGNATURE = 0x02;
BTChip.FEATURE_FREE_SIGHASHTYPE = 0x04;

BTChip.VERSION_BITCOIN_MAINNET = 0;
BTChip.VERSION_BITCOIN_P2SH_MAINNET = 5;

BTChip.QWERTY_KEYMAP = new ByteString("00271E1F202122232425260405060708090A0B0C0D0E0F101112131415161718191A1B1C1D372C28", HEX);
BTChip.AZERTY_KEYMAP = new ByteString("03271E1F202122232425261405060708090A0B0C0D0E0F331112130415161718191D1B1C1A362C28", HEX);

BTChip.QWERTY_KEYMAP_NEW = new ByteString("000000000000000000000000760f00d4ffffffc7000000782c1e3420212224342627252e362d3738271e1f202122232425263333362e37381f0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d2f3130232d350405060708090a0b0c0d0e0f101112131415161718191a1b1c1d2f313035", HEX);
BTChip.AZERTY_KEYMAP_NEW = new ByteString("08000000010000200100007820c8ffc3feffff07000000002c38202030341e21222d352e102e3637271e1f202122232425263736362e37101f1405060708090a0b0c0d0e0f331112130415161718191d1b1c1a2f64302f2d351405060708090a0b0c0d0e0f331112130415161718191d1b1c1a2f643035", HEX);

BTChip.KEY_PREPARE_FLAG_BASE58_ENCODED = 0x02;
BTChip.KEY_PREPARE_FLAG_HASH_SHA256 = 0x04;
BTChip.KEY_PREPARE_DERIVE = 0x08;
BTChip.KEY_PREPARE_FLAG_RAW = 0x20;

BTChip.SIGHASH_ALL = 1;

BTChip.EXTERNAL_CHAIN = 1;
BTChip.INTERNAL_CHAIN = 2;

BTChip.DEFAULT_LOCKTIME = new ByteString("00000000", HEX);


