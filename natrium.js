import * as sodium from 'libsodium-wrappers';


export class Natrium {
	size = {
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
	}

	random(size) {
		if(!Number.isInteger(size) || size < 1)
			return Promise.reject(new Error('size should be an integer number and greater than 0'));

		return new Promise(function(success) {
			success(sodium.randombytes_buf(size));
		});
	}

	random_seed() {
		return this.random(this.size.sign_seed);
	}

	sign_keypair(seed) {
		if(!Buffer.isBuffer(seed) || seed.length != this.size.sign_seed)
			return Promise.reject(new Error('seed should be a Buffer of size ' + this.size.sign_seed));

		return new Promise(function(success, fail) {
			sodium.sign_keypair(seed, function (error, pk, sk) {
				if(error)
					return fail(error);

				success({public: pk, secret: sk, seed});
			});
		});
	}

	new_sign_keypair() {
		return this.random_seed().then(seed => this.sign_keypair(seed));
	}

	sign(secret, message) {
		if(!Buffer.isBuffer(secret) || secret.length != this.size.sign_secret)
			return Promise.reject(new Error('secret should be a Buffer of size ' + this.size.sign_secret));

		if(!Buffer.isBuffer(message) || message.length === 0)
			return Promise.reject(new Error('message should be a Buffer of a size greater than 0'));

		return new Promise(function(success, fail) {
			sodium.sign(secret, message, function (error, signature) {
				if(error)
					return fail(error);

				success(signature);
			});
		});
	}

	verify(pk, signature, message) {
		if(!Buffer.isBuffer(pk) || pk.length != this.size.sign_public)
			return Promise.reject(new Error('public key should be a Buffer of size ' + this.size.sign_public));

		if(!Buffer.isBuffer(signature) || signature.length === 0)
			return Promise.reject(new Error('signature should be a Buffer of a size greater than 0'));

		if(!Buffer.isBuffer(message) || message.length === 0)
			return Promise.reject(new Error('message should be a Buffer of a size greater than 0'));

		return new Promise(function(success, fail) {
			sodium.verify(pk, signature, message, function (error) {
				if(error)
					return fail(error);

				success();
			});
		});
	}

	box_keypair() {
		return new Promise(function(success, fail) {
			sodium.box_keypair(function (error, pk, sk) {
				if(error)
					return fail(error);

				success({public: pk, secret: sk});
			});
		});
	}

	// secret is own secret key
	// pk is the someone else's public key
	box_key(secret, pk) {
		if(!Buffer.isBuffer(pk) || pk.length != this.size.box_public)
			return Promise.reject(new Error('public key should be a Buffer of size ' + this.size.box_public));

		if(!Buffer.isBuffer(secret) || secret.length != this.size.box_secret)
			return Promise.reject(new Error('secret key should be a Buffer of size ' + this.size.box_secret));

		return new Promise(function(success, fail) {
			sodium.box_key(pk, secret, function (error, key) {
				if(error)
					return fail(error);

				success(key);
			});
		});
	}

	zero(secret) {
		if(!Buffer.isBuffer(secret) || secret.length === 0)
			return Promise.reject(new Error('secret should be a Buffer of a size greater than 0'));

		return new Promise(function(success) {
			sodium.zero(secret, success);
		});
	}

	encrypt(key, message) {
		if(!Buffer.isBuffer(key) || key.length != this.size.box_key)
			return Promise.reject(new Error('shared key should be a Buffer of size ' + this.size.box_key));

		if(!Buffer.isBuffer(message) || message.length === 0)
			return Promise.reject(new Error('message should be a Buffer of size greater than 0'));

		return new Promise(function(success, fail) {
			sodium.encrypt(key, message, function (error, cipher) {
				if(error)
					return fail(error);

				success(cipher);
			});
		});
	}

	decrypt(key, cipher) {
		if(!Buffer.isBuffer(key) || key.length != this.size.box_key)
			return Promise.reject(new Error('shared key should be a Buffer of size ' + this.size.box_key));

		if(!Buffer.isBuffer(cipher) || cipher.length <= (this.size.box_nonce + this.size.box_mac))
			return Promise.reject(new Error('cipher should be a Buffer of size greater than ' + (this.size.box_nonce + this.size.box_mac)));

		return new Promise(function(success, fail) {
			sodium.decrypt(key, cipher, function (error, message) {
				if(error)
					return fail(error);

				success(message);
			});
		});
	}

	secretbox_key() {
		return new Promise(function(success) {
			sodium.secretbox_key(success);
		});
	}

	secretbox_encrypt(key, message) {
		if(!Buffer.isBuffer(key) || key.length != this.size.secretbox_key)
			return Promise.reject(new Error('shared key should be a Buffer of size ' + this.size.secretbox_key));

		if(!Buffer.isBuffer(message) || message.length === 0)
			return Promise.reject(new Error('message should be a Buffer of size greater than 0'));

		return new Promise(function(success, fail) {
			sodium.secretbox_encrypt(key, message, function (error, cipher) {
				if(error)
					return fail(error);

				success(cipher);
			});
		});
	}

	secretbox_decrypt(key, cipher) {
		if(!Buffer.isBuffer(key) || key.length != this.size.secretbox_key)
			return Promise.reject(new Error('shared key should be a Buffer of size ' + this.size.secretbox_key));

		if(!Buffer.isBuffer(cipher) || cipher.length <= (this.size.secretbox_nonce + this.size.secretbox_mac))
			return Promise.reject(new Error('cipher should be a Buffer of size greater than ' + (this.size.secretbox_nonce + this.size.secretbox_mac)));

		return new Promise(function(success, fail) {
			sodium.decrypt(key, cipher, function (error, message) {
				if(error)
					return fail(error);

				success(message);
			});
		});
	}
}

let na = new Natrium();
export default na;
