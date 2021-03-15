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
