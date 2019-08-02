# This file is provided for you to help with your implementation, DON'T submit this file.
# ONLY submit `lab10.py`

from hashlib import sha256

def sha256_hexoutput(in_str):
    """return sha-256 hash of the input 'in_str' 
    """
    return sha256(in_str.encode('ascii')).hexdigest()

def hash_answer(password_list):
    password_string = ''.join(password_list)
    return sha256_hexoutput(password_string)

# ------- Question 2 Helpers -------

from pcrypt import crypt

def hash_password(hash_id, salt, password):
    return crypt(password, '${}${}'.format(hash_id, salt))

sample_shadow_file = "root0:$6$jD/pkNvoMfUwKqqZ$vq0NVKYOCAMJdFeWmogiMoP3t/LeuELSLW7iGnOJjJM0L8NRLX/eNw07tegYwBSNJ2ZBsEcXvMKT6MXHPbCXf0:1337:0:99999:7:::\nroot1:$6$rSF.1OuM8$jXhsGQCd8p89yzYKokjNXhDlQG8ddW98h04Zd2E1NtM19NjKW/QVTnilAUuyWRV/g3uXmkS7altmnRN/qE2zO.:1337:0:99999:7:::\nroot2:$6$3UDvh99D3PiYV8Ty$MUNr0ksxA/A8.Bn4J5zmI0OLxxr52sDmZVn7gmh/xkcFMwz7SP6u/Y7i6nX4deQyZ8ngyEnuMVqfIie8KJWmj0:1337:0:99999:7:::\nroot3:$6$Pm9RcXpcw$41VQoy.QW41v9G78lLTL9tI2p8zflwhfsGIoFMtGsZ2R8OgNHqmo/OsIAhgLex.nPyNifXsFpWZ5JMrPAZXy71:1337:0:99999:7:::\nroot4:$6$BQsDwleg.eiAMar7$4524eWrQrutlM3SbkKBJ8kNCf0GdsoLds1GE16i7hPObo8bkIYkuBvcTfQRfTzpE69cS5VH5b66IrNMt5JHyz/:1337:0:99999:7:::\nroot5:$5$SkbAMf2EnIdCHx9M$1QXQdR7JKQ0ItrnAk5vF0Sr0Iatj5.AOzFrBvSFmrTB:1337:0:99999:7:::\nroot6:$5$SiMVUN.REdBfddB$hIJFa5uhHaTNJkb1tgvMxDUNkX7hbvVj0/ElM3cxA27:1337:0:99999:7:::\nroot7:$5$9asMN7L6AwoTstZ.$pZiPt1BBjYLyEsR9eQ3txtVhiI12wPOiqAAyJc9Xyk5:1337:0:99999:7:::\nroot8:$5$sLUITX50W3esQ$bDvt3fr4mAqXAb.O/MMs47Yna7FcJiHrZ1hl5xLbgZ1:1337:0:99999:7:::\nroot9:$5$hjrAUdgvGA8$VpAHSgsHEp5sgEFrj7FCAC17rx6lhRcXTa9vp558bE2:1337:0:99999:7:::\n"

# This list is extracted from the 'rockyou' password dump (more info:https://www.kaggle.com/wjburns/common-password-list-rockyoutxt)
top_rockyou_passwords = "123456\n12345\n123456789\npassword\niloveyou\nprincess\n1234567\nrockyou\n12345678\nabc123\nnicole\ndaniel\nbabygirl\nmonkey\nlovely\njessica\n654321\nmichael\nashley\nqwerty\n111111\niloveu\n000000\nmichelle\ntigger\nsunshine\nchocolate\npassword1\nsoccer\nanthony\nfriends\nbutterfly\npurple\nangel\njordan\nliverpool\njustin\nloveme\n123123\nfootball\nsecret\nandrea\ncarlos\njennifer\njoshua\nbubbles\n4881234567890\nsuperman\nhannah\namanda\n"
top_rockyou_passwords = top_rockyou_passwords.splitlines()
