# Recursion Reverse

## Description

Jimmy needs some help figuring out how computers process text, help him out!

## Solution

We're given the following Java source code:

```java
import java.util.Scanner;
public class AscII {
	static int num = 0;

	public static void main(String[] args) {
		 Scanner sc = new Scanner(System.in);
		 System.out.print("Enter your  guess: ");
		 String guess = sc.nextLine();

		 if (guess.length()!= 12)
			 System.out.println("Sorry, thats wrong.");
		 else {
			 if(flagTransformed(guess).equals("I$N]=6YiVwC"))
				 System.out.println("Yup the flag is flag{" + guess + "}");
			 else
				 System.out.println("nope");
		 }
	}

	public static String flagTransformed(String guess) {
		char[] transformed = new char[12];

		for(int i = 0; i < 12; i++) {
			num = 1;
			transformed[i] = (char)(((int)guess.charAt(i) + pickNum(i + 1)) % 127);
		}

		char[] temp = new char[12];
		for(int i = 11; i >= 0; i--)
			temp[11-i] = transformed[i];

		return new String(temp);
	}

	private static int pickNum(int i) {

		for(int x = 0; x <= i; x++)
			num+=x;

		if(num % 2 == 0)
			return num;
		else
			num = pickNum(num);

		return num;
	}
}
```

We can see that the user input is passed to the ```flagTransformed()``` and the return value is compared to a string, ```I$N]=6YiVwC```.

The ```flagTransformed()``` function performs two operations on the input string.
We can handle these operations separately when getting the flag from the key.

Let's look at the first loop:

```java
char[] transformed = new char[12];

for(int i = 0; i < 12; i++) {
    num = 1;
    transformed[i] = (char)(((int)guess.charAt(i) + pickNum(i + 1)) % 127);
}
```

The function adds the return value of ```pickNum(i + 1)``` to the value of the character as an integer, then performs a modular operation on the result.

Let's look at the ```pickNum()``` function:

```java
private static int pickNum(int i) {

    for(int x = 0; x <= i; x++)
        num+=x;

    if(num % 2 == 0)
        return num;
    else
        num = pickNum(num);

    return num;
}
```

The function is a recursive function, the result of which depends on the value of ```num``` and the parameter ```i```.
Fortunately, the value of ```num``` is set to 1 every time before the function is called.
We can find the offset applied by calling the same function, then subtract it from the character as an integer to get the original character.

To handle cases where subtracting this offset results in a negative number, we can simply add 127 until the number is greater than 0.
127 is the maximum value for ASCII characters, so the original character won't have been greater.

The second part of the function is much simpler:

```java
char[] temp = new char[12];
for(int i = 11; i >= 0; i--)
    temp[11-i] = transformed[i];
```

Here, we can see that the order of the characters is reversed.

By reversing both processes in the correct order, we are given the flag.

## Script

```java
public class AscIIDecoder {
	static int num = 0;
	
	public static void main(String[] args) {
        System.out.println("Yup the flag is flag{" + deTransform("I$N]=6YiVwC") + "}");			 
	}
	
	public static String flagTransformed(String guess) {
		char[] transformed = new char[12];
		
		for(int i = 0; i < 12; i++) {
			num = 1;
			transformed[i] = (char)(((int)guess.charAt(i) + pickNum(i + 1)) % 127);	
		}
		
		char[] temp = new char[12];		
		for(int i = 11; i >= 0; i--) 
			temp[11-i] = transformed[i];
			
		return new String(temp);	
	}

    public static String deTransform(String encoded) {
        char[] temp = new char[12];
        for(int i = 0; i < 12; i++) {
            temp[11-i] = encoded.charAt(i);
        }

        char[] flag = new char[12];
        int[] flagints = new int[12];
        for(int i = 0; i < 12; i++) {
            num = 1;
            flagints[i] = (int)temp[i] - pickNum(i + 1) + 254;
            while(flagints[i] < 0) flagints[i] += 127;
            flag[i] = (char)(flagints[i] % 127);
        }
        return new String(flag);
    }
	
	private static int pickNum(int i) {
		
		for(int x = 0; x <= i; x++)
			num+=x;
		
		if(num % 2 == 0)
			return num;
		else 
			num = pickNum(num);
		
		return num;		
	}	 
}
```

## Flag

```flag{AscII is key}```

