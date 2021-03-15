public class AscIIDecoder {
	static int num = 0;
	
	public static void main(String[] args) {
        System.out.println("Yup the flag is flag{" + deTransform("I$N]=6YiVwC") + "}");			 
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
