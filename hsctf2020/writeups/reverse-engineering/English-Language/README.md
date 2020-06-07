# AP Lab: English Language

## Description

The AP English Language activity will ask you to reverse a program about manipulating strings and arrays. Again, an output will be given where you have to reconstruct an input.

## Solution

We're given Java source code as follows:

```java
import java.util.Scanner;
public class EnglishLanguage
{
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        String inp = sc.nextLine();
        if (inp.length()!=23) {
            System.out.println("Your input is incorrect.");
            System.exit(0);
        }
        for (int i = 0; i<3; i++) {
            inp=transpose(inp);
            inp=xor(inp);
        }
        if (inp.equals("1dd3|y_3tttb5g`q]^dhn3j")) {
            System.out.println("Correct. Your input is the flag.");
        }
        else {
            System.out.println("Your input is incorrect.");
        }
    }
    public static String transpose(String input) {
        int[] transpose = {11,18,15,19,8,17,5,2,12,6,21,0,22,7,13,14,4,16,20,1,3,10,9};
        String ret = "";
        for (int i: transpose) {
            ret+=input.charAt(i);
        }
        return ret;
    }
    public static String xor(String input) {
        int[] xor = {4,1,3,1,2,1,3,0,1,4,3,1,2,0,1,4,1,2,3,2,1,0,3};
        String ret = "";
        for (int i = 0; i<input.length(); i++) {
            ret+=(char)(input.charAt(i)^xor[i]) ;
        }
        return ret;
    }
}
```

We can see that two operations are performed on our input, ```transpose()``` and ```xor()``` and the result is checked against a string, ```1dd3|y_3tttb5g`q]^dhn3j```.

Let's take a look at the ```transpose()``` function:

```java
public static String transpose(String input) {
    int[] transpose = {11,18,15,19,8,17,5,2,12,6,21,0,22,7,13,14,4,16,20,1,3,10,9};
    String ret = "";
    for (int i: transpose) {
        ret+=input.charAt(i);
    }
    return ret;
}
```

We can see that the function uses an array ```int[] transpose``` to rearrange the original characters, taking the character at the index listed in the array.

We can reverse this process by getting the index of the original position in this array.
For example, for the first character, we'd find where ```0``` is in the array, and use the character at that index.
This can be done using a single line of Java:

```java
ret+=input.charAt(Arrays.asList(transpose).indexOf(i));
```

And we can reuse the exact array from the original code.

Next, lets look at the ```xor()``` function:

```java
public static String xor(String input) {
    int[] xor = {4,1,3,1,2,1,3,0,1,4,3,1,2,0,1,4,1,2,3,2,1,0,3};
    String ret = "";
    for (int i = 0; i<input.length(); i++) {
        ret+=(char)(input.charAt(i)^xor[i]) ;
    }
    return ret;
}
```

The characters of the original string are XORed with a value from an array, ```int[] xor```.
Due to the nature of XOR operations, we can simply reuse this function to undo the process.

Using the encoded string as the input and undoing the transformations in the correct order gives us the flag.

## Script

```java
import java.util.Arrays;
public class EnglishLanguageDecoder
{
    public static void main(String[] args) {
        String inp = "1dd3|y_3tttb5g`q]^dhn3j";
        for (int i = 0; i<3; i++) {
            inp=xor(inp);
            inp=detranspose(inp);
        }
        System.out.println(inp);
    }
    public static String detranspose(String input) {
        Integer[] transpose = {11,18,15,19,8,17,5,2,12,6,21,0,22,7,13,14,4,16,20,1,3,10,9};
        String ret = "";
        for (int i = 0; i<input.length(); i++) {
            ret+=input.charAt(Arrays.asList(transpose).indexOf(i));
        }
        return ret;
    }
    public static String xor(String input) {
        int[] xor = {4,1,3,1,2,1,3,0,1,4,3,1,2,0,1,4,1,2,3,2,1,0,3};
        String ret = "";
        for (int i = 0; i<input.length(); i++) {
            ret+=(char)(input.charAt(i)^xor[i]) ;
        }
        return ret;
    }
}
```

## Flag

```flag{n0t_t00_b4d_r1ght}```

