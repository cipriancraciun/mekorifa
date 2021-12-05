

#![ allow (unused_parens) ]
#![ allow (dead_code) ]




use ::ring;

use ::hex_literal::hex;




pub struct Envelope {
	pub password_parameters : PasswordParameters,
	pub password_salt : PasswordSalt,
	pub token_identifier : TokenIdentifier,
	pub token_description : TokenDescription,
	pub token_encrypted : TokenDataEncrypted,
	pub authentication_only_token : AuthenticationTagOnlyToken,
	pub authentication_with_data : AuthenticationTagWithData,
	pub checksum : EnvelopeChecksum,
}




pub struct TokenIdentifier (pub MessageDataFixed<TOKEN_IDENTIFIER_SIZE>);
pub struct TokenDescription (pub MessageDataVariable);
pub struct TokenDataDecrypted (pub MessageDataVariable);
pub struct TokenDataEncrypted (pub MessageDataVariable);

pub const TOKEN_IDENTIFIER_SIZE : usize = 128 / 8;


pub struct PasswordText (pub KeyDataVariable);
pub struct PasswordSalt (pub KeyDataFixed<PASSWORD_SALT_SIZE>);

pub const PASSWORD_SALT_SIZE : usize = 512 / 8;


pub struct EncryptionKey (pub KeyDataFixed<ENCRYPTION_KEY_SIZE>);
pub struct EncryptionNonce (pub KeyDataFixed<ENCRYPTION_NONCE_SIZE>);

pub const ENCRYPTION_KEY_SIZE : usize = 256 / 8;
pub const ENCRYPTION_NONCE_SIZE : usize = 96 / 8;


pub struct AuthenticationKeyOnlyToken (pub KeyDataFixed<AUTHENTICATION_KEY_SIZE>);
pub struct AuthenticationKeyWithData (pub KeyDataFixed<AUTHENTICATION_KEY_SIZE>);

pub const AUTHENTICATION_KEY_SIZE : usize = 256 / 8;


pub struct EncryptedMessage (pub MessageDataVariable);
pub struct DecryptedMessage (pub MessageDataVariable);

pub struct AdditionalData (pub MessageDataVariable);


pub struct AuthenticationTagOnlyToken (pub MessageDataFixed<AUTHENTICATION_TAG_SIZE>);
pub struct AuthenticationTagWithData (pub MessageDataFixed<AUTHENTICATION_TAG_SIZE>);

pub const AUTHENTICATION_TAG_SIZE : usize = 256 / 8;


pub struct EnvelopeChecksum (pub MessageDataFixed<ENVELOPE_CHECKSUM_SIZE>);

pub const ENVELOPE_CHECKSUM_SIZE : usize = 256 / 8;




pub struct PasswordParameters {
	pub n_log2 : u32,
	pub r : u32,
	pub p : u32,
}




pub struct KeyDataFixed <const S : usize> (pub Box<[u8; S]>);
pub struct KeyDataVariable (pub Box<[u8]>);

pub struct MessageDataFixed <const S : usize> (pub Box<[u8; S]>);
pub struct MessageDataVariable (pub Box<[u8]>);




pub struct NamespaceNonce (pub [u8; 64]);

pub const PASSWORD_NAMESPACE : NamespaceNonce = NamespaceNonce (hex! ("d189ed7d155a5c47d3e6a99b66727a54bc9cde60a8f7061b2d563800292f5fc05f915bb0e676b17ae5ffb3ae29819e3511169a342862ff389ab131d26c708b92"));
pub const AUTHENTICATION_NAMESPACE_ONLY_TOKEN : NamespaceNonce = NamespaceNonce (hex! ("bcb1c8046960c27009d6da3948ae9db8c8ea963c1f88a612b14525a4a8fd0261876cea2cbe38ea278a803b0ba0ff7bf3a9bae40380e9f666a6608c36aede33f3"));
pub const AUTHENTICATION_NAMESPACE_WITH_DATA : NamespaceNonce = NamespaceNonce (hex! ("4fced4c26b5cc4047b309ab9cbf1378796f70db8f341c596ca614b73125b71bb091fd2669157b0b0979cec2e140a2156dae9731f56453fbfc29f06b1409c9da5"));
pub const ENVELOPE_CHECKSUM_NAMESPACE : NamespaceNonce = NamespaceNonce (hex! ("e7c2f948611eea1f2cb3543ab799e9d3ce1372a638847d484fd9d02852517e8a24889351b2b88bd3ea1ce24f17394cf6416438868406e36bdcc2efb87b04f8c7"));




pub fn password_derive
		(
			_password_text : PasswordText,
			_password_salt : PasswordSalt,
			_password_parameters : PasswordParameters,
			_namespace : NamespaceNonce,
		) -> (
			EncryptionKey,
			EncryptionNonce,
			AuthenticationKeyOnlyToken,
			AuthenticationKeyWithData,
		)
{
	unimplemented! ("[c2f6f10d]");
}




pub fn message_encrypt
		(
			
			_decrypted_message : DecryptedMessage,
			_additional_data : AdditionalData,
			_encryption_key : EncryptionKey,
			_encryption_nonce : EncryptionNonce,
			
			_authentication_key_only_token : AuthenticationKeyOnlyToken,
			_authentication_namespace_only_token : NamespaceNonce,
			
			_authentication_key_with_data : AuthenticationKeyWithData,
			_authentication_namespace_with_data : NamespaceNonce,
			
		) -> (
			EncryptedMessage,
			AuthenticationTagOnlyToken,
			AuthenticationTagWithData,
		)
{
	unimplemented! ("[6f1f528f]");
}




pub fn message_decrypt
		(
			
			_encrypted_message : EncryptedMessage,
			_additional_data : AdditionalData,
			_encryption_key : EncryptionKey,
			_encryption_nonce : EncryptionNonce,
			
			_authentication_tag_only_token : AuthenticationTagOnlyToken,
			_authentication_key_only_token : AuthenticationKeyOnlyToken,
			_authentication_namespace_only_token : NamespaceNonce,
			
			_authentication_tag_with_data : AuthenticationTagWithData,
			_authentication_key_with_data : AuthenticationKeyWithData,
			_authentication_namespace_with_data : NamespaceNonce,
			
		) -> (
			Result<DecryptedMessage, ()>,
		)
{
	unimplemented! ("[f221babb]");
}




pub fn envelope_checksum (_envelope : Envelope) -> Result<(), ()>
{
	unimplemented! ("[e56a27ad]");
}




pub fn envelope_encrypt
		(
			_password_text : PasswordText,
			_password_parameters : Option<PasswordParameters>,
			_token_identifier : TokenIdentifier,
			_token_description : TokenDescription,
			_token_data_decrypted : TokenDataDecrypted,
		) -> (
			Result<Envelope, ()>,
		)
{
	unimplemented! ("[7ce61d1d]");
}




pub fn envelope_decrypt
		(
			_password_text : PasswordText,
			_envelope : Envelope,
		) -> (
			Result<TokenDataDecrypted, ()>,
		)
{
	unimplemented! ("[2fc9c0a9]");
}




pub trait BytesFixed <const S : usize>
	where Self : Sized
{
	
	fn from_bytes (_bytes : Box<[u8; S]>) -> (Self);
	
	fn new_random () -> (Self)
	{
		let _bytes = [0; S];
		let mut _bytes = Box::new (_bytes);
		random_fill (&mut _bytes[..]);
		Self::from_bytes (_bytes)
	}
}


pub trait BytesVariable
	where Self : Sized
{
	
	fn from_bytes (_bytes : Box<[u8]>) -> (Self);
	
	fn new_random (_size : usize) -> (Self)
	{
		let mut _bytes = Vec::new ();
		_bytes.reserve_exact (_size);
		let mut _bytes = _bytes.into_boxed_slice ();
		random_fill (&mut _bytes[..]);
		Self::from_bytes (_bytes)
	}
}




impl <const S : usize> BytesFixed<S> for KeyDataFixed<S> {
	
	fn from_bytes (_bytes : Box<[u8; S]>) -> (Self) {
		Self (_bytes)
	}
}

impl <const S : usize> BytesFixed<S> for MessageDataFixed<S> {
	
	fn from_bytes (_bytes : Box<[u8; S]>) -> (Self) {
		Self (_bytes)
	}
}


impl BytesVariable for KeyDataVariable {
	
	fn from_bytes (_bytes : Box<[u8]>) -> (Self) {
		Self (_bytes)
	}
}

impl BytesVariable for MessageDataVariable {
	
	fn from_bytes (_bytes : Box<[u8]>) -> (Self) {
		Self (_bytes)
	}
}




fn random_fill (_buffer : &mut [u8])
{
	let _generator = ring::rand::SystemRandom::new ();
	_generator.fill (_buffer) .expect ("[11b27ca4]");
}




use ::ring::rand::SecureRandom as _;

