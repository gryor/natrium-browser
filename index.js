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
			if (!seed instanceof Uint8Array || seed.length != this.size.sign_seed) return Promise.reject(new Error('seed should be a Buffer of size ' + this.size.sign_seed));

			var me = this;

			return new Promise(function (success, fail) {
				var keypair = sodium.crypto_sign_seed_keypair(seed);
				keypair = { secret: keypair.privateKey, 'public': keypair.publicKey, seed: seed };

				if (keypair.secret instanceof Uint8Array && keypair['public'] instanceof Uint8Array) if (keypair.secret.length === me.size.sign_secret && keypair['public'].length === me.size.sign_public) return success(keypair);

				return fail(new Error('Sign keypair generation failed', keypair));
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
			if (!secret instanceof Uint8Array || secret.length != this.size.sign_secret) return Promise.reject(new Error('secret should be a Buffer of size ' + this.size.sign_secret));

			if (!message instanceof Uint8Array || message.length === 0) return Promise.reject(new Error('message should be a Buffer of a size greater than 0'));

			var me = this;

			return new Promise(function (success, fail) {
				var signature = sodium.crypto_sign_detached(message, secret);

				if (signature instanceof Uint8Array && signature.length === me.size.signature) return success(signature);

				return fail(new Error('Signature generation failed', signature));
			});
		}
	}, {
		key: 'verify',
		value: function verify(pk, signature, message) {
			if (!pk instanceof Uint8Array || pk.length != this.size.sign_public) return Promise.reject(new Error('public key should be a Buffer of size ' + this.size.sign_public));

			if (!signature instanceof Uint8Array || signature.length === 0) return Promise.reject(new Error('signature should be a Buffer of a size greater than 0'));

			if (!message instanceof Uint8Array || message.length === 0) return Promise.reject(new Error('message should be a Buffer of a size greater than 0'));

			return new Promise(function (success, fail) {
				var verified = sodium.crypto_sign_verify_detached(signature, message, pk);

				if (verified) return success();

				return fail(new Error('Verification failed'));
			});
		}
	}, {
		key: 'box_keypair',
		value: function box_keypair() {
			var me = this;

			return new Promise(function (success, fail) {
				var keypair = sodium.crypto_box_keypair();
				keypair = { secret: keypair.privateKey, 'public': keypair.publicKey };

				if (keypair.secret instanceof Uint8Array && keypair['public'] instanceof Uint8Array) if (keypair.secret.length === me.size.box_secret && keypair['public'].length === me.size.box_public) return success(keypair);

				return fail(new Error('Box keypair generation failed', keypair));
			});
		}

		// secret is own secret key
		// pk is the someone else's public key
	}, {
		key: 'box_key',
		value: function box_key(secret, pk) {
			if (!pk instanceof Uint8Array || pk.length != this.size.box_public) return Promise.reject(new Error('public key should be a Buffer of size ' + this.size.box_public));

			if (!secret instanceof Uint8Array || secret.length != this.size.box_secret) return Promise.reject(new Error('secret key should be a Buffer of size ' + this.size.box_secret));

			var me = this;

			return new Promise(function (success, fail) {
				var key = sodium.crypto_box_beforenm(pk, secret);

				if (key instanceof Uint8Array && key.length === me.size.box_key) return success(key);

				return fail(new Error('Box key generation failed', key));
			});
		}
	}, {
		key: 'zero',
		value: function zero(secret) {
			if (!secret instanceof Uint8Array || secret.length === 0) return Promise.reject(new Error('secret should be a Buffer of a size greater than 0'));

			return new Promise(function (success) {
				for (var i = 0; i < secret.length; i++) {
					secret[i] = 0;
				}success();
			});
		}
	}, {
		key: 'encrypt',
		value: function encrypt(key, message) {
			if (!key instanceof Uint8Array || key.length != this.size.box_key) return Promise.reject(new Error('shared key should be a Buffer of size ' + this.size.box_key));

			if (!message instanceof Uint8Array || message.length === 0) return Promise.reject(new Error('message should be a Buffer of size greater than 0'));

			var me = this;

			return this.random(this.size.box_nonce).then(function (nonce) {
				return new Promise(function (success, fail) {
					var cipher = sodium.crypto_box_easy_afternm(message, nonce, key);
					//cipher = Uint8Array.of(nonce, cipher);
					var cipher_tmp = new Uint8Array(nonce.length + cipher.length);

					cipher_tmp.set(nonce);
					cipher_tmp.set(cipher, nonce.length);
					cipher = cipher_tmp;
					// REMOVE cipher_tmp when Uint8Array.of is implemented!!!

					if (cipher instanceof Uint8Array && cipher.length === me.size.box_nonce + message.length + me.size.box_mac) success(cipher);

					return fail(new Error('Box encrypt failed', cipher));
				});
			});
		}
	}, {
		key: 'decrypt',
		value: function decrypt(key, cipher) {
			if (!key instanceof Uint8Array || key.length != this.size.box_key) return Promise.reject(new Error('shared key should be a Buffer of size ' + this.size.box_key));

			if (!cipher instanceof Uint8Array || cipher.length <= this.size.box_nonce + this.size.box_mac) return Promise.reject(new Error('cipher should be a Buffer of size greater than ' + (this.size.box_nonce + this.size.box_mac)));

			var me = this;

			return new Promise(function (success, fail) {
				var info = { cipher: cipher.subarray(me.size.box_nonce), nonce: cipher.subarray(0, me.size.box_nonce) };
				var message = sodium.crypto_box_open_easy_afternm(info.cipher, info.nonce, key);

				if (message instanceof Uint8Array && message.length === cipher.length - me.size.box_nonce - me.size.box_mac) return success(message);

				return fail('Box decrypt failed', message);
			});
		}
	}, {
		key: 'secretbox_key',
		value: function secretbox_key() {
			return this.random(this.size.secretbox_key);
		}
	}, {
		key: 'secretbox_encrypt',
		value: function secretbox_encrypt(key, message) {
			if (!key instanceof Uint8Array || key.length != this.size.secretbox_key) return Promise.reject(new Error('shared key should be a Buffer of size ' + this.size.secretbox_key));

			if (!message instanceof Uint8Array || message.length === 0) return Promise.reject(new Error('message should be a Buffer of size greater than 0'));

			var me = this;

			return this.random(this.size.secretbox_nonce).then(function (nonce) {
				return new Promise(function (success, fail) {
					var cipher = sodium.crypto_secretbox_easy(message, nonce, key);
					//cipher = Uint8Array.of(nonce, cipher);
					var cipher_tmp = new Uint8Array(nonce.length + cipher.length);

					cipher_tmp.set(nonce);
					cipher_tmp.set(cipher, nonce.length);
					cipher = cipher_tmp;
					// REMOVE cipher_tmp when Uint8Array.of is implemented!!!

					if (cipher instanceof Uint8Array && cipher.length === me.size.secretbox_nonce + me.size.secretbox_mac + message.length) return success(cipher);

					return fail('Secretbox encrypt failed', cipher);
				});
			});
		}
	}, {
		key: 'secretbox_decrypt',
		value: function secretbox_decrypt(key, cipher) {
			if (!key instanceof Uint8Array || key.length != this.size.secretbox_key) return Promise.reject(new Error('shared key should be a Buffer of size ' + this.size.secretbox_key));

			if (!cipher instanceof Uint8Array || cipher.length <= this.size.secretbox_nonce + this.size.secretbox_mac) return Promise.reject(new Error('cipher should be a Buffer of size greater than ' + (this.size.secretbox_nonce + this.size.secretbox_mac)));

			var me = this;

			return new Promise(function (success, fail) {
				var info = { cipher: cipher.subarray(me.size.secretbox_nonce), nonce: cipher.subarray(0, me.size.secretbox_nonce) };
				var message = sodium.crypto_secretbox_open_easy(info.cipher, info.nonce, key);

				if (message instanceof Uint8Array && message.length === cipher.length - me.size.secretbox_nonce - me.size.secretbox_mac) return success(message);

				return fail('Secretbox decrypt failed', message);
			});
		}
	}]);

	return Natrium;
})();

exports.Natrium = Natrium;

var na = new Natrium();
exports['default'] = na;
