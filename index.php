<?php

    error_reporting(E_ALL);

    require_once "native_lib/unicode_lib.php";
    require_once "native_lib/crypto_lib.php";


    if (!empty($_POST["user_string"]) && !empty($_POST["user_password"])) {
        if ($_POST['encryption_algorithm'] == "Caesar"){
            $user_string = $_POST["user_string"];
            $user_password = $_POST["user_password"];
            $encrypted_result = get_cesar_encryption($user_string, (int)$user_password);
            $decrypted_result = get_cesar_decryption($encrypted_result, (int)$user_password);
        }
        if ($_POST['encryption_algorithm'] == "Polyalphabetic"){
            $user_string = $_POST["user_string"];
            $user_password = $_POST["user_password"];
            $encrypted_result = get_polyalphabetic_encryption($user_string, $user_password);
            $decrypted_result = get_polyalphabetic_decryption($encrypted_result, $user_password);
        }
        if ($_POST['encryption_algorithm'] == "Monoalphabetic"){
            $user_string = $_POST["user_string"];
            $user_password = $_POST["user_password"];
            $encrypted_result = get_monoalphabetic_encryption($user_string, $user_password);
            $decrypted_result = get_monoalphabetic_decryption($encrypted_result, $user_password);
        }
        if ($_POST['encryption_algorithm'] == "Bigram"){
            $user_string = $_POST["user_string"];
            $user_password = $_POST["user_password"];
            $encrypted_result = get_bigram_encryption($user_string, $user_password);
            $encrypted_result['encrypted_data_string'] = '';
            for ($i = 0; $i < count($encrypted_result['encrypted_data_unicode_list']); $i++){
                $encrypted_result['encrypted_data_string'] .= ($encrypted_result['encrypted_data_unicode_list'][$i]) . ' ';
            }
            $decrypted_result = get_bigram_decryption($encrypted_result, $user_password);
        }
    }

?>


<!DOCTYPE HTML>
<html>
    <head>
        <meta charset="utf-8">
        <title>STUDENT_PROJECT</title>
    </head>
    <body>
    <h1>Учебный студенческий проект по криптографии</h1>
    <form name="user_data" action="" method="post">
        <p>Текст для шифрования:</p>
        <p><textarea rows="10" cols="60" name="user_string"></textarea></p>
        <p>PASSWORD <input type="text" name="user_password"></p>
        <select name = "encryption_algorithm">
            <option value = "Caesar" selected>Шифр Цезаря</option>
            <option value = "Polyalphabetic">Полиалфавитный шифр</option>
            <option value = "Monoalphabetic">Моноалфавитный шифр</option>
            <option value = "Bigram">Биграммный шифр</option>
        </select>
        <p><input type="submit" value="Отправить"></p>
        <br><hr><br>
        <p>Вы ввели для шифрования:</p>
        <p><textarea rows="10" cols="60" name="user_sent" readonly><?if(isset($_POST["user_string"])){print($_POST["user_string"]);}?></textarea></p>
        <br><hr><br>
        <p>Шифротекст (это не то, что передаём другому проекту -- передаём то, что в следующем секторе!):</p>
        <p><textarea rows="10" cols="60" name="encrypted_result" readonly><?if(isset($encrypted_result)){print($encrypted_result['encrypted_data_string']);}?></textarea></p>
        <br><hr><br>
        <p>Зашифрованные данные для передачи другому проекту (пока тут формат json не соблюдается, это только примерно)</p>
        <p><textarea rows="30" cols="160" name="encrypted_result_struct" readonly><?if(isset($encrypted_result)){print_r($encrypted_result);}?></textarea></p>
        <br><hr><br>
        <p>Тут же расшифровали на том же ключе (должно совпадать с тем, что ты вводил для шифрования):</p>
        <p><textarea rows="10" cols="60" name="decrypted_result" readonly><?if(isset($decrypted_result)){print($decrypted_result['decrypted_data_string']);}?></textarea></p>
    </form>
    </body>
</html>

<!--
FOR TESTING SERVICE YOU CAN USE THIS UNICODE INPUT STRING:
======BEGIN======
1234567890
!"№;%:?*()
The quick brown fox jumps over the lazy dog
Съешь же ещё этих мягких французских булок да выпей чаю
Η ισχύς εν τη ενώσει
思い煩う事はない。人生に意味などあるわけがないのだ。
☹😡🙀🚜©✘↷♥🎧👍
======END======
-->