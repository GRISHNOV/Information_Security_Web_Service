import * as cryptico from "./RsaSrc/cryptico"; // https://github.com/wwwtyro/cryptico
import { Base64 } from './RsaSrc/base64'; // https://github.com/dankogai/js-base64

export function generateRSAOpenKey(KeyPhrase: string, RsaKeyLength: number){
    /*
    *   Params:
    *   KeyPhrase: this is password from user (can be any utf-8 string).
    *   RsaKeyLength: use 512 or 1024 (rsa key pair length).
    *
    *   Purpose:
    *   Generates the RSA key pair and extracts the public key from it for return.
    *   Also returns the md5 key for integrity control.
    */
    const RSAKeyPair: object = cryptico.generateRSAKey(KeyPhrase, RsaKeyLength);
    const OpenKeyValue: string = cryptico.publicKeyString(RSAKeyPair);
    const OpenKeyMD5Value: string = cryptico.publicKeyID(OpenKeyValue);
    return {
        "open_rsa_key": OpenKeyValue,
        "key_md5": OpenKeyMD5Value,
    }; // Please, do not change this returning object fields -- this is important for synchronization.
}

export function encryptRSA(OpenKeyValue: string, OpenKeyMD5Value:string, PlainTextValue: string){
    /*
    *   Params:
    *   OpenKeyValue: open key for encryption
    *   OpenKeyMD5Value: check open key for integrity before encryption
    *   PlainTextValue: message from user
    *
    *   Purpose:
    *   Performs encryption on the user's public key.
    *   Checks the integrity of the public key before encryption.
    */
    if (OpenKeyMD5Value !== cryptico.publicKeyID(OpenKeyValue)){
        return {
            "encrypted_data": "ERROR: the open key was damaged!"
        };
    }
    const EncryptionResult: object = cryptico.encrypt(Base64.encode(PlainTextValue), OpenKeyValue);
    const CloseText: string = EncryptionResult['cipher'];
    return {
        "encryption_result": CloseText,
    }; // Please, do not change this returning object fields -- this is important for synchronization.
}

export function decryptRSA(CloseText: string, KeyPhrase: string, RsaKeyLength: number){
    /*
    *   Params:
    *   CloseText: encrypted text
    *   KeyPhrase: this is password from user (can be any utf-8 string).
    *   RsaKeyLength: use 512 or 1024 (rsa key pair length).
    *
    *   Purpose:
    *   Performs decryption.
    *   To get the private key, use the user's passphrase that was used when creating the public key.
    */
    const RSAKeyPair: object = cryptico.generateRSAKey(KeyPhrase, RsaKeyLength);
    const DecryptionResult: object = cryptico.decrypt(CloseText, RSAKeyPair);
    const DecryptedText: string = Base64.decode(DecryptionResult['plaintext']);
    return {
        'decrypted_text': DecryptedText,
    }; // Please, do not change this returning object fields -- this is important for synchronization.
}
