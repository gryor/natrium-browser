'use strict';

Object.defineProperty(exports, '__esModule', {
	value: true
});

var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj['default'] = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }

var _libsodiumWrappers = require('libsodium-wrappers');

var sodium = _interopRequireWildcard(_libsodiumWrappers);

var Natrium = (function () {
	function Natrium() {
		_classCallCheck(this, Natrium);

		this.size = {
			sign_public: sodium.crypto_sign_PUBLICKEYBYTES,
			sign_secret: sodium.crypto_sign_SECRETKEYBYTES,
			sign_seed: sodium.crypto_sign_SEEDBYTES,
			signature: sodium.crypto_sign_BYTES,
			box_public: sodium.crypto_box_PUBLICKEYBYTES,
			box_secret: sodium.crypto_box_SECRETKEYBYTES,
			box_key: sodium.crypto_box_SECRETKEYBYTES,
			box_nonce: sodium.crypto_box_NONCEBYTES,
			box_mac: sodium.crypto_box_MACBYTES,
			secretbox_key: sodium.crypto_secretbox_KEYBYTES,
			secretbox_nonce: sodium.crypto_secretbox_NONCEBYTES,
			secretbox_mac: sodium.crypto_secretbox_MACBYTES
		};
	}

	_createClass(Natrium, [{
		key: 'random',
		value: function random(size) {
			if (!Number.isInteger(size) || size < 1) return Promise.reject(new Error('size should be an integer number and greater than 0'));

			return new Promise(function (success) {
				success(sodium.randombytes_buf(size));
			});
		}
	}, {
		key: 'random_seed',
		value: function random_seed() {
			return this.random(this.size.sign_seed);
		}
	}, {
		key: 'sign_keypair',
		value: function sign_keypair(seed) {
			if (!Buffer.isBuffer(seed) || seed.length != this.size.sign_seed) return Promise.reject(new Error('seed should be a Buffer of size ' + this.size.sign_seed));

			return new Promise(function (success, fail) {
				sodium.sign_keypair(seed, function (error, pk, sk) {
					if (error) return fail(error);

					success({ 'public': pk, secret: sk, seed: seed });
				});
			});
		}
	}, {
		key: 'new_sign_keypair',
		value: function new_sign_keypair() {
			var _this = this;

			return this.random_seed().then(function (seed) {
				return _this.sign_keypair(seed);
			});
		}
	}, {
		key: 'sign',
		value: function sign(secret, message) {
			if (!Buffer.isBuffer(secret) || secret.length != this.size.sign_secret) return Promise.reject(new Error('secret should be a Buffer of size ' + this.size.sign_secret));

			if (!Buffer.isBuffer(message) || message.length === 0) return Promise.reject(new Error('message should be a Buffer of a size greater than 0'));

			return new Promise(function (success, fail) {
				sodium.sign(secret, message, function (error, signature) {
					if (error) return fail(error);

					success(signature);
				});
			});
		}
	}, {
		key: 'verify',
		value: function verify(pk, signature, message) {
			if (!Buffer.isBuffer(pk) || pk.length != this.size.sign_public) return Promise.reject(new Error('public key should be a Buffer of size ' + this.size.sign_public));

			if (!Buffer.isBuffer(signature) || signature.length === 0) return Promise.reject(new Error('signature should be a Buffer of a size greater than 0'));

			if (!Buffer.isBuffer(message) || message.length === 0) return Promise.reject(new Error('message should be a Buffer of a size greater than 0'));

			return new Promise(function (success, fail) {
				sodium.verify(pk, signature, message, function (error) {
					if (error) return fail(error);

					success();
				});
			});
		}
	}, {
		key: 'box_keypair',
		value: function box_keypair() {
			return new Promise(function (success, fail) {
				sodium.box_keypair(function (error, pk, sk) {
					if (error) return fail(error);

					success({ 'public': pk, secret: sk });
				});
			});
		}

		// secret is own secret key
		// pk is the someone else's public key
	}, {
		key: 'box_key',
		value: function box_key(secret, pk) {
			if (!Buffer.isBuffer(pk) || pk.length != this.size.box_public) return Promise.reject(new Error('public key should be a Buffer of size ' + this.size.box_public));

			if (!Buffer.isBuffer(secret) || secret.length != this.size.box_secret) return Promise.reject(new Error('secret key should be a Buffer of size ' + this.size.box_secret));

			return new Promise(function (success, fail) {
				sodium.box_key(pk, secret, function (error, key) {
					if (error) return fail(error);

					success(key);
				});
			});
		}
	}, {
		key: 'zero',
		value: function zero(secret) {
			if (!Buffer.isBuffer(secret) || secret.length === 0) return Promise.reject(new Error('secret should be a Buffer of a size greater than 0'));

			return new Promise(function (success) {
				sodium.zero(secret, success);
			});
		}
	}, {
		key: 'encrypt',
		value: function encrypt(key, message) {
			if (!Buffer.isBuffer(key) || key.length != this.size.box_key) return Promise.reject(new Error('shared key should be a Buffer of size ' + this.size.box_key));

			if (!Buffer.isBuffer(message) || message.length === 0) return Promise.reject(new Error('message should be a Buffer of size greater than 0'));

			return new Promise(function (success, fail) {
				sodium.encrypt(key, message, function (error, cipher) {
					if (error) return fail(error);

					success(cipher);
				});
			});
		}
	}, {
		key: 'decrypt',
		value: function decrypt(key, cipher) {
			if (!Buffer.isBuffer(key) || key.length != this.size.box_key) return Promise.reject(new Error('shared key should be a Buffer of size ' + this.size.box_key));

			if (!Buffer.isBuffer(cipher) || cipher.length <= this.size.box_nonce + this.size.box_mac) return Promise.reject(new Error('cipher should be a Buffer of size greater than ' + (this.size.box_nonce + this.size.box_mac)));

			return new Promise(function (success, fail) {
				sodium.decrypt(key, cipher, function (error, message) {
					if (error) return fail(error);

					success(message);
				});
			});
		}
	}, {
		key: 'secretbox_key',
		value: function secretbox_key() {
			return new Promise(function (success) {
				sodium.secretbox_key(success);
			});
		}
	}, {
		key: 'secretbox_encrypt',
		value: function secretbox_encrypt(key, message) {
			if (!Buffer.isBuffer(key) || key.length != this.size.secretbox_key) return Promise.reject(new Error('shared key should be a Buffer of size ' + this.size.secretbox_key));

			if (!Buffer.isBuffer(message) || message.length === 0) return Promise.reject(new Error('message should be a Buffer of size greater than 0'));

			return new Promise(function (success, fail) {
				sodium.secretbox_encrypt(key, message, function (error, cipher) {
					if (error) return fail(error);

					success(cipher);
				});
			});
		}
	}, {
		key: 'secretbox_decrypt',
		value: function secretbox_decrypt(key, cipher) {
			if (!Buffer.isBuffer(key) || key.length != this.size.secretbox_key) return Promise.reject(new Error('shared key should be a Buffer of size ' + this.size.secretbox_key));

			if (!Buffer.isBuffer(cipher) || cipher.length <= this.size.secretbox_nonce + this.size.secretbox_mac) return Promise.reject(new Error('cipher should be a Buffer of size greater than ' + (this.size.secretbox_nonce + this.size.secretbox_mac)));

			return new Promise(function (success, fail) {
				sodium.decrypt(key, cipher, function (error, message) {
					if (error) return fail(error);

					success(message);
				});
			});
		}
	}]);

	return Natrium;
})();

exports.Natrium = Natrium;

var na = new Natrium();
exports['default'] = na;
