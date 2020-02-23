<?php

    /*
     *      Functions for working with UNICODE symbols in PHP.
     *      MIPT cryptography course project, 2020
     */

    function uniord($ch) {
        $n = ord($ch{0});
        if ($n < 128) {
            return $n; // no conversion required
        }
        if ($n < 192 || $n > 253) {
            return false; // bad first byte || out of range
        }
        $arr = array(1 => 192, // byte position => range from
            2 => 224,
            3 => 240,
            4 => 248,
            5 => 252,
        );
        foreach ($arr as $key => $val) {
            if ($n >= $val) { // add byte to the 'char' array
                $char[] = ord($ch{$key}) - 128;
                $range  = $val;
            } else {
                break; // save some e-trees
            }
        }
        $retval = ($n - $range) * pow(64, sizeof($char));
        foreach ($char as $key => $val) {
            $pow = sizeof($char) - ($key + 1); // invert key
            $retval += $val * pow(64, $pow);   // dark magic
        }
        return $retval;
    }


    function uchr ($codes) {
        if (is_scalar($codes)) $codes= func_get_args();
        $str= '';
        foreach ($codes as $code) $str.= html_entity_decode('&#'.$code.';',ENT_NOQUOTES,'UTF-8');
        return $str;
    }
