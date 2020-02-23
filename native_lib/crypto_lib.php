<?php

    /*
     *      _____Cryptographic Function Library_____
     *
     *      Ciphers in the current version of the library:
     *
     *      CESAR: YES
     *      POLYALPHABETIC[Vigenère]: YES
     *      MONOALPHABETIC: YES
     *      BIGRAM: YES
     *
     *      MIPT cryptography course project, 2020
     */


    require_once "unicode_lib.php";


    function get_cesar_encryption($data_string, $key){
        $data_chars_array = preg_split('//u', $data_string, NULL, PREG_SPLIT_NO_EMPTY);
        $encrypted_data_unicode_list = array();
        $encrypted_data_string = "";
        for ($i = 0; $i < count($data_chars_array); $i++){
            array_push($encrypted_data_unicode_list, (uniord($data_chars_array[$i]) + $key) % 1114111);
            $encrypted_data_string .= uchr((uniord($data_chars_array[$i]) + $key) % 1114111);
        }
        return ['encrypted_data_string' => $encrypted_data_string, 'encrypted_data_unicode_list' => $encrypted_data_unicode_list];
    }


    function get_cesar_decryption($data_struct, $key){
        $data_chars_array = $data_struct['encrypted_data_unicode_list'];
        $decrypted_data_unicode_list = array();
        $decrypted_data_string = "";
        for ($i = 0; $i < count($data_chars_array); $i++){
            array_push($decrypted_data_unicode_list, ($data_chars_array[$i] - $key) % 1114111);
            $decrypted_data_string .= uchr(($data_chars_array[$i] - $key) % 1114111);
        }
        return ['decrypted_data_string' => $decrypted_data_string, 'decrypted_data_unicode_list' => $decrypted_data_unicode_list];
    }


    function get_monoalphabetic_encryption($data_string, $key){
        $key_code = 0;
        for ($i = 0; $i < strlen($key); $i++){
            $key_code += uniord($key[$i]);
        }
        $data_chars_array = preg_split('//u', $data_string, NULL, PREG_SPLIT_NO_EMPTY);
        $encrypted_data_unicode_list = array();
        $encrypted_data_string = "";
        for ($i = 0; $i < count($data_chars_array); $i++){
            array_push($encrypted_data_unicode_list, (uniord($data_chars_array[$i]) + $key_code) % 1114111);
            $encrypted_data_string .= uchr((uniord($data_chars_array[$i]) + $key_code) % 1114111);
        }
        return ['encrypted_data_string' => $encrypted_data_string, 'encrypted_data_unicode_list' => $encrypted_data_unicode_list];

    }


    function get_monoalphabetic_decryption($data_struct, $key){
        $key_code = 0;
        for ($i = 0; $i < strlen($key); $i++){
            $key_code += uniord($key[$i]);
        }
        $decrypted_data_unicode_list = array();
        $decrypted_data_string = "";
        $data_chars_array = $data_struct['encrypted_data_unicode_list'];
        for ($i = 0; $i < count($data_chars_array); $i++){
            array_push($decrypted_data_unicode_list, ($data_chars_array[$i] - $key_code) % 1114111);
            $decrypted_data_string .= uchr(($data_chars_array[$i] - $key_code) % 1114111);
        }
        return ['decrypted_data_string' => $decrypted_data_string, 'decrypted_data_unicode_list' => $decrypted_data_unicode_list];
    }


    function get_polyalphabetic_encryption($data_string, $key) {
        $data_chars_array = preg_split('//u', $data_string, NULL, PREG_SPLIT_NO_EMPTY);
        $key_material = '';
        while (strlen($key_material) < count($data_chars_array)){
            $key_material .= $key;
        }
        $key_material = substr($key_material,0, count($data_chars_array));
        $encrypted_data_unicode_list = array();
        $encrypted_data_string = "";
        for ($i = 0; $i < count($data_chars_array); $i++){
            array_push($encrypted_data_unicode_list, (uniord($data_chars_array[$i]) + uniord($key_material[$i])) % 1114112);
            $encrypted_data_string .= uchr((uniord($data_chars_array[$i]) + uniord($key_material[$i])) % 1114112);
        }
        return ['encrypted_data_string' => $encrypted_data_string, 'encrypted_data_unicode_list' => $encrypted_data_unicode_list];
    }


    function get_polyalphabetic_decryption($data_struct, $key){
        $data_chars_array = $data_struct['encrypted_data_unicode_list'];
        $key_material = '';
        while (strlen($key_material) < count($data_chars_array)){
            $key_material .= $key;
        }
        $key_material = substr($key_material,0, count($data_chars_array));
        $decrypted_data_unicode_list = array();
        $decrypted_data_string = "";
        for ($i = 0; $i < count($data_chars_array); $i++){
            array_push($decrypted_data_unicode_list, ($data_chars_array[$i] + 1114112 - uniord($key_material[$i])) % 1114112);
            $decrypted_data_string .= uchr(($data_chars_array[$i] + 1114112 - uniord($key_material[$i])) % 1114112);
        }
        return ['decrypted_data_string' => $decrypted_data_string, 'decrypted_data_unicode_list' => $decrypted_data_unicode_list];
    }

    function get_bigram_encryption($data_string, $key){
        $key_code = 0;
        for ($i = 0; $i < strlen($key); $i++){
            $key_code += uniord($key[$i]);
        }
        if (strlen($data_string) % 2 != 0){
            $data_string .= ' ';
        }
        $data_chars_array = preg_split('//u', $data_string, NULL, PREG_SPLIT_NO_EMPTY);
        $encrypted_data_unicode_list = array();
        for ($i = 0; $i < count($data_chars_array) - 1; $i += 2){
            array_push($encrypted_data_unicode_list, uniord($data_chars_array[$i])*1114112 + uniord($data_chars_array[$i + 1]) + $key_code);
        }
        return ['encrypted_data_unicode_list' => $encrypted_data_unicode_list];
    }

    function get_bigram_decryption($data_struct, $key){
        $data_chars_array = $data_struct['encrypted_data_unicode_list'];
        $key_code = 0;
        for ($i = 0; $i < strlen($key); $i++){
            $key_code += uniord($key[$i]);
        }
        $decrypted_data_unicode_list = array();
        $decrypted_data_string = "";
        $stop_search_flag = false;
        for ($code_iterator = 0; $code_iterator < count($data_chars_array); $code_iterator++){;
            for ($i = intdiv ($data_chars_array[$code_iterator], 1114112); $i < 1114112; $i++){
                if ($stop_search_flag != true){
                    for ($j = 0; $j < 1114112; $j++){
                        if($i*1114112 + $j + $key_code == $data_chars_array[$code_iterator]){
                            array_push($decrypted_data_unicode_list, $i);
                            array_push($decrypted_data_unicode_list, $j);
                            $decrypted_data_string .=  uchr($i) . uchr($j);
                            $stop_search_flag = true;
                            break;
                        }
                    }
                }else{
                    $stop_search_flag = false;
                    break;
                }
            }
        }
        return ['decrypted_data_string' => $decrypted_data_string, 'decrypted_data_unicode_list' => $decrypted_data_unicode_list];
    }