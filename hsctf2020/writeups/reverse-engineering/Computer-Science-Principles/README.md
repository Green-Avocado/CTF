# AP Lab: Computer Science Principles

## Description

This activity will ask you to reverse a basic program and solve an introductory reversing challenge. You will be given an output that is to be used in order to reconstruct the input, which is the flag.

## Solution

We're given Java source code as follows:

```java
import java.util.Scanner;
public class ComputerSciencePrinciples
{
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        String inp = sc.nextLine();
        if (inp.length()!=18) {
            System.out.println("Your input is incorrect.");
            System.exit(0);
        }
        inp=shift2(shift(inp));
        if (inp.equals("inagzgkpm)Wl&Tg&io")) {
            System.out.println("Correct. Your input is the flag.");
        }
        else {
            System.out.println("Your input is incorrect.");
        }
        System.out.println(inp);
    }
    public static String shift(String input) {
        String ret = "";
        for (int i = 0; i<input.length(); i++) {
            ret+=(char)(input.charAt(i)-i);
        }
        return ret;
    }
    public static String shift2(String input) {
        String ret = "";
        for (int i = 0; i<input.length(); i++) {
            ret+=(char)(input.charAt(i)+Integer.toString((int)input.charAt(i)).length());
        }
        return ret;
    }
}
```

The program takes a string from user input, performs two operations on it, ```shift()``` and ```shift2()```, then compares it to another string, ```inagzgkpm)Wl&Tg&io```.

Lets take a look at how the ```shift()``` function works.

```java
public static String shift(String input) {
    String ret = "";
    for (int i = 0; i<input.length(); i++) {
        ret+=(char)(input.charAt(i)-i);
    }
    return ret;
}
```

The function loops through every character, in the correct order, and appends a character to a ```ret``` string, which is returned.

We can see that the character being appended is shifted by ```-i``` from the original character, where ```i``` is the index of the character.

This process is easily reversed by shifting the character by ```+i```, as the index is not changed by this process, so the value of ```i``` is the same in both cases.

Next, lets look at the ```shift2()``` function.

```java
public static String shift2(String input) {
    String ret = "";
    for (int i = 0; i<input.length(); i++) {
        ret+=(char)(input.charAt(i)+Integer.toString((int)input.charAt(i)).length());
    }
    return ret;
}
```

This function shifts each character by the length of the decimal representation of that character.

Plain-text characters will be represented by decimal values 32 - 126, therefore, this shift will either be ```+2``` or ```+3```.

If the original character had a decimal value < 100, it would be shifted by 2.
Otherwise, it would be shifted by 3.
Therefore, we can reliably determine the length of the original decimal value by taking the decimal value of a character with a value of 2 less than the current value.

Using this information, we can easily undo this process.

## Script

```py
#!/usr/bin/python

def unshift(encrypted):
    ret = ""
    for i in range(len(encrypted)):
        ret += chr(ord(encrypted[i]) + i)
    return ret

def unshift2(encrypted):
    ret = ""
    for i in range(len(encrypted)):
        ret += chr(ord(encrypted[i]) - len(str(ord(encrypted[i]) - 2)))
    return ret

print(unshift(unshift2("inagzgkpm)Wl&Tg&io")))
```

## Flag

```flag{intr0_t0_r3v}```

