def checkpass():
    _input = input("Enter the password: ").encode()
    if _input[0:4].hex() == "63617374":
        if _input[4:9].hex() == "6f72734354":
            if _input[9:14].hex() == "467b723178":
                if _input[14:17].hex() == "54795f":
                    if _input[17:20].hex() == "6d316e":
                        if _input[20:27].hex() == "757433735f6774":
                            if _input[27:35].hex() == "5f73317874795f6d":
                                if _input[35:40].hex() == "316e757433":
                                    if _input[40:].hex() == "737d":
                                        return True

def main():
    global access
    access = checkpass()
    if access:
        print("Yeah...okay. You got it!")
    else:
        print("Lol...try again...")

access = False
main()