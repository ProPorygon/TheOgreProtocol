def pad_message(message):
    """
    Pads a string for use with AES encryption
    :param message: string to be padded
    :return: padded message
    """
    pad_size = 128 - len(message) % 128
    if pad_size == 0:
        pad_size = 128
    message += "0" * pad_size
    return message
