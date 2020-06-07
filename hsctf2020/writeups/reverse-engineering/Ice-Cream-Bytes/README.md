# Ice Cream Bytes

## Description

Introducing the new Ice Cream Bytes machine! Here’s a free trial: [IceCreamBytes.java](./IceCreamBytes.java) Oh, and make sure to read the user manual: [IceCreamManual.txt](./IceCreamManual.txt)

## Solution

We're given Java source code as follows:

```java
import java.io.*;
import java.nio.file.*;
import java.util.Scanner;

public class IceCreamBytes {
    public static void main(String[] args) throws IOException {
        Path path = Paths.get("IceCreamManual.txt");
        byte[] manualBytes = Files.readAllBytes(path);

        Scanner keyboard = new Scanner(System.in);
        System.out.print("Enter the password to the ice cream machine: ");
        String userInput = keyboard.next();
        String input = userInput.substring("flag{".length(), userInput.length()-1);
        byte[] loadedBytes = toppings(chocolateShuffle(vanillaShuffle(strawberryShuffle(input.getBytes()))));
        boolean correctPassword = true;

        byte[] correctBytes = fillMachine(manualBytes);
        for (int i = 0; i < correctBytes.length; i++) {
            if (loadedBytes[i] != correctBytes[i]) {
                correctPassword  = false;
            }
        }
        if (correctPassword) {
            System.out.println("That's right! Enjoy your ice cream!");
        } else {
            System.out.println("Uhhh that's not right.");
        }
        keyboard.close();
    }

    public static byte[] fillMachine(byte[] inputIceCream) {
        byte[] outputIceCream = new byte[34];
        int[] intGredients = {27, 120, 79, 80, 147,
            154, 97, 8, 13, 46, 31, 54, 15, 112, 3,
            464, 116, 58, 87, 120, 139, 75, 6, 182,
            9, 153, 53, 7, 42, 23, 24, 159, 41, 110};
        for (int i = 0; i < outputIceCream.length; i++) {
            outputIceCream[i] = inputIceCream[intGredients[i]];
        }
        return outputIceCream;
    }

    public static byte[] strawberryShuffle(byte[] inputIceCream) {
        byte[] outputIceCream = new byte[inputIceCream.length];
        for (int i = 0; i < outputIceCream.length; i++) {
            outputIceCream[i] = inputIceCream[inputIceCream.length - i - 1];
        }
        return outputIceCream;
    }

    public static byte[] vanillaShuffle(byte[] inputIceCream) {
        byte[] outputIceCream = new byte[inputIceCream.length];
        for (int i = 0; i < outputIceCream.length; i++) {
            if (i % 2 == 0) {
                outputIceCream[i] = (byte)(inputIceCream[i] + 1);
            } else {
                outputIceCream[i] = (byte)(inputIceCream[i] - 1);
            }
        }
        return outputIceCream;
    }

    public static byte[] chocolateShuffle(byte[] inputIceCream) {
        byte[] outputIceCream = new byte[inputIceCream.length];
        for (int i = 0; i < outputIceCream.length; i++) {
            if (i % 2 == 0) {
                if (i > 0) {
                    outputIceCream[i] = inputIceCream[i - 2];
                } else {
                    outputIceCream[i] = inputIceCream[inputIceCream.length - 2];
                }
            } else {
                if (i < outputIceCream.length - 2) {
                    outputIceCream[i] = inputIceCream[i + 2];
                } else {
                    outputIceCream[i] = inputIceCream[1];
                }
            }
        }
        return outputIceCream;
    }

    public static byte[] toppings(byte[] inputIceCream) {
        byte[] outputIceCream = new byte[inputIceCream.length];
        byte[] toppings = {8, 61, -8, -7, 58, 55,
            -8, 49, 20, 65, -7, 54, -8, 66, -9, 69,
            20, -9, -12, -4, 20, 5, 62, 3, -13, 66,
            8, 3, 56, 47, -5, 13, 1, -7,};
        for (int i = 0; i < outputIceCream.length; i++) {
            outputIceCream[i] = (byte)(inputIceCream[i] + toppings[i]);
        }
        return outputIceCream;

    }

}
```

The code takes user input and performs a series of operations on it: ```strawverrySuffle()```, ```vanillaShuffle()```, ```chocolateShuffle()```, and ```toppings()```.

The result is compared against an array of bytes, ```byte[] correctBytes```, which is populated using the ```fillMachine()``` function and passing bytes from the ```IceCreamManual.txt``` file.

If we look at the manual, we find that there's nothing interesting, though it is necessary for this challenge as the source of the key.

```
*Ice Cream Bytes User Manual*
The Ice Cream Bytes Machine is a device specifically designed in making a special treat known as Ice Cream Bytes!
In order to ensure a successful creation process, please follow the directions as listed below:
Here are the ingredients you will need to use to get started with making Ice Cream Bytes:
1. Milk
2. Sugar
3. Cream
4. Any other toppings you desire!
Firstly, place the desired ingredients in the corresponding dispensers.
Next, enter the correct password, and select the correct settings to begin the ice cream creation process.
Make sure the ice cream machine is secure and to ensure that the lid does not overfill.
When the green light appears, you may remove the container from the rest of the machine. Enjoy!
Here are some troubleshooting tips:
1. Ensure that the machine does not run for longer than 5 minutes in a row.
2. It is helpful to mix some of the ingredients first in order to make the process go smoothly.
3. Before using the machine, ensure the light is not red. If so, let the machine cool for 10-15 minutes before use.
For extra help, please contact the manufacturer as printed on the label.
We hope you enjoy using your new Ice Cream Bytes Machine!
```

Now lets look at each of the manipulations of our input, starting with ```strawberryShuffle()```:

```java
public static byte[] strawberryShuffle(byte[] inputIceCream) {
    byte[] outputIceCream = new byte[inputIceCream.length];
    for (int i = 0; i < outputIceCream.length; i++) {
        outputIceCream[i] = inputIceCream[inputIceCream.length - i - 1];
    }
    return outputIceCream;
}
```

The function simply reverses the order of the input.
This can be easily reversed by running the output back through this exact function.

The next operation is ```vanillaShuffle()```, which looks like this:

```java
public static byte[] vanillaShuffle(byte[] inputIceCream) {
    byte[] outputIceCream = new byte[inputIceCream.length];
    for (int i = 0; i < outputIceCream.length; i++) {
        if (i % 2 == 0) {
            outputIceCream[i] = (byte)(inputIceCream[i] + 1);
        } else {
            outputIceCream[i] = (byte)(inputIceCream[i] - 1);
        }
    }
    return outputIceCream;
}
```

This function changes the value of each byte depending on whether the index is divisible by 2.
To reverse this, we can make a function identical to this, except we flip the signed so that indices divisible two are decreased, and those that aren't are increased

Next is the ```chocolateShuffle()``` function:

```java
public static byte[] chocolateShuffle(byte[] inputIceCream) {
    byte[] outputIceCream = new byte[inputIceCream.length];
    for (int i = 0; i < outputIceCream.length; i++) {
        if (i % 2 == 0) {
            if (i > 0) {
                outputIceCream[i] = inputIceCream[i - 2];
            } else {
                outputIceCream[i] = inputIceCream[inputIceCream.length - 2];
            }
        } else {
            if (i < outputIceCream.length - 2) {
                outputIceCream[i] = inputIceCream[i + 2];
            } else {
                outputIceCream[i] = inputIceCream[1];
            }
        }
    }
    return outputIceCream;
}
```

This function is a bit more complicated, let's use a short example to map it out.

If we look briefly at the ```fillMachine()``` function, we can see that the byte arrays will be 34 bytes long, so our example should also be an even number.

```java
byte[] outputIceCream = new byte[34];
```

Lets use 8 bytes for our example, allowing us enough space to recognise any patterns.

```
0 1 2 3 4 5 6 7
```

Working our way through the ```chocolateShuffle()``` function logically, we'd see that our example is rearranged to:

```
6 3 0 5 2 7 4 1
```

The function simply moves even indicies 2 places to the right, and odd ones 2 places to the left, wrapping where necessary.

We can reverse this process fairly simply by modifying the existing function to shift these values the opposite direction, again wrapping where necessary.

The last function we need to look at is the ```toppings()``` function:

```java
public static byte[] toppings(byte[] inputIceCream) {
    byte[] outputIceCream = new byte[inputIceCream.length];
    byte[] toppings = {8, 61, -8, -7, 58, 55,
        -8, 49, 20, 65, -7, 54, -8, 66, -9, 69,
        20, -9, -12, -4, 20, 5, 62, 3, -13, 66,
        8, 3, 56, 47, -5, 13, 1, -7,};
    for (int i = 0; i < outputIceCream.length; i++) {
        outputIceCream[i] = (byte)(inputIceCream[i] + toppings[i]);
    }
    return outputIceCream;

}
```

The values of the input array are shifted by an amount from a ```byte[] toppings``` array.
This can be reversed by simply subtracting the corresponding value, using the same array.

Reversing these functions in the correct order gives us the flag.

## Script

```py
import java.io.*;
import java.nio.file.*;
import java.util.Scanner;

public class IceCreamBytesDecoder {
    public static void main(String[] args) throws IOException {
        Path path = Paths.get("IceCreamManual.txt");
        byte[] manualBytes = Files.readAllBytes(path);

        byte[] correctBytes = fillMachine(manualBytes);
        byte[] loadedBytes = new byte[correctBytes.length];
        for (int i = 0; i < correctBytes.length; i++) {
            loadedBytes[i] = correctBytes[i];
        }
        byte[] result = destrawberryShuffle(devanillaShuffle(dechocolateShuffle(detoppings(loadedBytes))));
        System.out.println(new String(correctBytes));
        System.out.println(new String(result));
    }


    public static byte[] strawberryShuffle(byte[] inputIceCream) {
        byte[] outputIceCream = new byte[inputIceCream.length];
        for (int i = 0; i < outputIceCream.length; i++) {
            outputIceCream[i] = inputIceCream[inputIceCream.length - i - 1];
        }
        return outputIceCream;
    }

    public static byte[] vanillaShuffle(byte[] inputIceCream) {
        byte[] outputIceCream = new byte[inputIceCream.length];
        for (int i = 0; i < outputIceCream.length; i++) {
            if (i % 2 == 0) {
                outputIceCream[i] = (byte)(inputIceCream[i] + 1);
            } else {
                outputIceCream[i] = (byte)(inputIceCream[i] - 1);
            }
        }
        return outputIceCream;
    }

    public static byte[] chocolateShuffle(byte[] inputIceCream) {
        byte[] outputIceCream = new byte[inputIceCream.length];
        for (int i = 0; i < outputIceCream.length; i++) {
            if (i % 2 == 0) {
                if (i > 0) {
                    outputIceCream[i] = inputIceCream[i - 2];
                } else {
                    outputIceCream[i] = inputIceCream[inputIceCream.length - 2];
                }
            } else {
                if (i < outputIceCream.length - 2) {
                    outputIceCream[i] = inputIceCream[i + 2];
                } else {
                    outputIceCream[i] = inputIceCream[1];
                }
            }
        }
        return outputIceCream;
    }

    public static byte[] toppings(byte[] inputIceCream) {
        byte[] outputIceCream = new byte[inputIceCream.length];
        byte[] toppings = {8, 61, -8, -7, 58, 55,
            -8, 49, 20, 65, -7, 54, -8, 66, -9, 69,
            20, -9, -12, -4, 20, 5, 62, 3, -13, 66,
            8, 3, 56, 47, -5, 13, 1, -7,};
        for (int i = 0; i < outputIceCream.length; i++) {
            outputIceCream[i] = (byte)(inputIceCream[i] + toppings[i]);
        }
        return outputIceCream;

    }


    public static byte[] fillMachine(byte[] inputIceCream) {
        byte[] outputIceCream = new byte[34];
        int[] intGredients = {27, 120, 79, 80, 147,
            154, 97, 8, 13, 46, 31, 54, 15, 112, 3,
            464, 116, 58, 87, 120, 139, 75, 6, 182,
            9, 153, 53, 7, 42, 23, 24, 159, 41, 110};
        for (int i = 0; i < outputIceCream.length; i++) {
            outputIceCream[i] = inputIceCream[intGredients[i]];
        }
        return outputIceCream;
    }

    public static byte[] destrawberryShuffle(byte[] inputIceCream) { //reverse
        byte[] outputIceCream = new byte[inputIceCream.length];
        for (int i = 0; i < outputIceCream.length; i++) {
            outputIceCream[i] = inputIceCream[inputIceCream.length - i - 1];
        }
        return outputIceCream;
    }

    public static byte[] devanillaShuffle(byte[] inputIceCream) { //shift based on index
        byte[] outputIceCream = new byte[inputIceCream.length];
        for (int i = 0; i < outputIceCream.length; i++) {
            if (i % 2 == 0) {
                outputIceCream[i] = (byte)(inputIceCream[i] - 1);
            } else {
                outputIceCream[i] = (byte)(inputIceCream[i] + 1);
            }
        }
        return outputIceCream;
    }

    public static byte[] dechocolateShuffle(byte[] inputIceCream) { //rearrange
        byte[] outputIceCream = new byte[inputIceCream.length];
        for (int i = 0; i < outputIceCream.length; i++) {
            if (i % 2 == 0) {
                if (i < inputIceCream.length - 2) {
                    outputIceCream[i] = inputIceCream[i + 2];
                } else {
                    outputIceCream[i] = inputIceCream[0];
                }
            } else {
                if (i > 1) {
                    outputIceCream[i] = inputIceCream[i - 2];
                } else {
                    outputIceCream[i] = inputIceCream[inputIceCream.length - 1];
                }
            }
        }
        return outputIceCream;
    }

    public static byte[] detoppings(byte[] inputIceCream) { //shift by toppings
        byte[] outputIceCream = new byte[inputIceCream.length];
        byte[] toppings = {8, 61, -8, -7, 58, 55,
            -8, 49, 20, 65, -7, 54, -8, 66, -9, 69,
            20, -9, -12, -4, 20, 5, 62, 3, -13, 66,
            8, 3, 56, 47, -5, 13, 1, -7,};
        for (int i = 0; i < outputIceCream.length; i++) {
            outputIceCream[i] = (byte)(inputIceCream[i] - toppings[i]);
        }
        return outputIceCream;

    }

}
```

## Flag

```flag{ic3_cr34m_byt3s_4r3_4m4z1n9_tr34ts}```

