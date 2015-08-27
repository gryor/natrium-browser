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
		if(!seed instanceof Uint8Array || seed.length != this.size.sign_seed)
			return Promise.reject(new Error('seed should be a Buffer of size ' + this.size.sign_seed));

		let me = this;

		return new Promise(function(success, fail) {
			let keypair = sodium.crypto_sign_seed_keypair(seed);
			keypair = {secret: keypair.privateKey, public: keypair.publicKey, seed};

			if(keypair.secret instanceof Uint8Array && keypair.public instanceof Uint8Array)
				if(keypair.secret.length === me.size.sign_secret && keypair.public.length === me.size.sign_public)
					return success(keypair);

			return fail(new Error('Sign keypair generation failed', keypair));
		});
	}

	new_sign_keypair() {
		return this.random_seed().then(seed => this.sign_keypair(seed));
	}

	sign(secret, message) {
		if(!secret instanceof Uint8Array || secret.length != this.size.sign_secret)
			return Promise.reject(new Error('secret should be a Buffer of size ' + this.size.sign_secret));

		if(!message instanceof Uint8Array || message.length === 0)
			return Promise.reject(new Error('message should be a Buffer of a size greater than 0'));

		let me = this;

		return new Promise(function(success, fail) {
			let signature = sodium.crypto_sign_detached(message, secret);

			if(signature instanceof Uint8Array && signature.length === me.size.signature)
				return success(signature);

			return fail(new Error('Signature generation failed', signature));
		});
	}

	verify(pk, signature, message) {
		if(!pk instanceof Uint8Array || pk.length != this.size.sign_public)
			return Promise.reject(new Error('public key should be a Buffer of size ' + this.size.sign_public));

		if(!signature instanceof Uint8Array || signature.length === 0)
			return Promise.reject(new Error('signature should be a Buffer of a size greater than 0'));

		if(!message instanceof Uint8Array || message.length === 0)
			return Promise.reject(new Error('message should be a Buffer of a size greater than 0'));

		return new Promise(function(success, fail) {
			let verified = sodium.crypto_sign_verify_detached(signature, message, pk);

			if(verified)
				return success();

			return fail(new Error('Verification failed'));
		});
	}

	box_keypair() {
		let me = this;

		return new Promise(function(success, fail) {
			let keypair = sodium.crypto_box_keypair();
			keypair = {secret: keypair.privateKey, public: keypair.publicKey};

			if(keypair.secret instanceof Uint8Array && keypair.public instanceof Uint8Array)
				if(keypair.secret.length === me.size.box_secret && keypair.public.length === me.size.box_public)
					return success(keypair);

			return fail(new Error('Box keypair generation failed', keypair));
		});
	}

	// secret is own secret key
	// pk is the someone else's public key
	box_key(secret, pk) {
		if(!pk instanceof Uint8Array || pk.length != this.size.box_public)
			return Promise.reject(new Error('public key should be a Buffer of size ' + this.size.box_public));

		if(!secret instanceof Uint8Array || secret.length != this.size.box_secret)
			return Promise.reject(new Error('secret key should be a Buffer of size ' + this.size.box_secret));

		let me = this;

		return new Promise(function(success, fail) {
			let key = sodium.crypto_box_beforenm(pk, secret);

			if(key instanceof Uint8Array && key.length === me.size.box_key)
				return success(key);

			return fail(new Error('Box key generation failed', key));
		});
	}

	zero(secret) {
		if(!secret instanceof Uint8Array || secret.length === 0)
			return Promise.reject(new Error('secret should be a Buffer of a size greater than 0'));

		return new Promise(function(success) {
			for(let i = 0; i < secret.length; i++)
			secret[i] = 0;

			success();
		});
	}

	encrypt(key, message) {
		if(!key instanceof Uint8Array || key.length != this.size.box_key)
			return Promise.reject(new Error('shared key should be a Buffer of size ' + this.size.box_key));

		if(!message instanceof Uint8Array || message.length === 0)
			return Promise.reject(new Error('message should be a Buffer of size greater than 0'));

		let me = this;

		return this.random(this.size.box_nonce).then(function (nonce) {
			return new Promise(function(success, fail) {
				let cipher = sodium.crypto_box_easy_afternm(message, nonce, key);
				//cipher = Uint8Array.of(nonce, cipher);
				let cipher_tmp = new Uint8Array(nonce.length + cipher.length);

				cipher_tmp.set(nonce);
				cipher_tmp.set(cipher, nonce.length);
				cipher = cipher_tmp;
				// REMOVE cipher_tmp when Uint8Array.of is implemented!!!

				if(cipher instanceof Uint8Array && cipher.length === (me.size.box_nonce + message.length + me.size.box_mac))
					success(cipher);

				return fail(new Error('Box encrypt failed', cipher));
			});
		});
	}

	decrypt(key, cipher) {
		if(!key instanceof Uint8Array || key.length != this.size.box_key)
			return Promise.reject(new Error('shared key should be a Buffer of size ' + this.size.box_key));

		if(!cipher instanceof Uint8Array || cipher.length <= (this.size.box_nonce + this.size.box_mac))
			return Promise.reject(new Error('cipher should be a Buffer of size greater than ' + (this.size.box_nonce + this.size.box_mac)));

		let me = this;

		return new Promise(function(success, fail) {
			let info = {cipher: cipher.subarray(me.size.box_nonce), nonce: cipher.subarray(0, me.size.box_nonce)};
			let message = sodium.crypto_box_open_easy_afternm(info.cipher, info.nonce, key);

			if(message instanceof Uint8Array && message.length === (cipher.length - me.size.box_nonce - me.size.box_mac))
				return success(message);

			return fail('Box decrypt failed', message);
		});
	}

	secretbox_key() {
		return this.random(this.size.secretbox_key);
	}

	secretbox_encrypt(key, message) {
		if(!key instanceof Uint8Array || key.length != this.size.secretbox_key)
			return Promise.reject(new Error('shared key should be a Buffer of size ' + this.size.secretbox_key));

		if(!message instanceof Uint8Array || message.length === 0)
			return Promise.reject(new Error('message should be a Buffer of size greater than 0'));

		let me = this;

		return this.random(this.size.secretbox_nonce).then(function (nonce) {
			return new Promise(function(success, fail) {
				let cipher = sodium.crypto_secretbox_easy(message, nonce, key);
				//cipher = Uint8Array.of(nonce, cipher);
				let cipher_tmp = new Uint8Array(nonce.length + cipher.length);

				cipher_tmp.set(nonce);
				cipher_tmp.set(cipher, nonce.length);
				cipher = cipher_tmp;
				// REMOVE cipher_tmp when Uint8Array.of is implemented!!!

				if(cipher instanceof Uint8Array && cipher.length === (me.size.secretbox_nonce + me.size.secretbox_mac + message.length))
					return success(cipher);

				return fail('Secretbox encrypt failed', cipher);
			});
		});
	}

	secretbox_decrypt(key, cipher) {
		if(!key instanceof Uint8Array || key.length != this.size.secretbox_key)
			return Promise.reject(new Error('shared key should be a Buffer of size ' + this.size.secretbox_key));

		if(!cipher instanceof Uint8Array || cipher.length <= (this.size.secretbox_nonce + this.size.secretbox_mac))
			return Promise.reject(new Error('cipher should be a Buffer of size greater than ' + (this.size.secretbox_nonce + this.size.secretbox_mac)));

		let me = this;

		return new Promise(function(success, fail) {
			let info = {cipher: cipher.subarray(me.size.secretbox_nonce), nonce: cipher.subarray(0, me.size.secretbox_nonce)};
			let message = sodium.crypto_secretbox_open_easy(info.cipher, info.nonce, key);

			if(message instanceof Uint8Array && message.length === (cipher.length - me.size.secretbox_nonce - me.size.secretbox_mac))
				return success(message);

			return fail('Secretbox decrypt failed', message);
		});
	}
}

let na = new Natrium();
export default na;
