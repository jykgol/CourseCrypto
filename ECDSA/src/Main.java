import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;

public class Main {
   private final static int MENUITEM_EXIT = 3; 
   private static ECParameterSpec p;
   private static BufferedReader buf = new BufferedReader(new InputStreamReader(System.in));
   private static int Number;
   private static ECPoint[] Pi;
   private static BigInteger[] Hi;
   private static BigInteger e;
   private static BigInteger S;
   private static ECPoint G;
   
   public static void main(String[] args)
   {
       int menuItem = 0;
       do
           try
           {
               switch(menuItem = getMenuItem())
               {
                   case 1: Generate_ECDSA();break;
                   case 2: Verify_ECDSA();break;
                   case 3: break;
                   default: System.out.println("\nUnknown menu item\n");
               }
           }
           catch(Exception ex)
           {
               System.out.println(ex);
           }
       while(menuItem != MENUITEM_EXIT);
   }
   
   private static int getMenuItem() throws Exception
   {
       System.out.println("Menu");
       System.out.println("----------------------------------");
       System.out.println("1. Sign message");
       System.out.println("2. Verify ECDSA");
       System.out.println("3. Exite");
       System.out.println("-----------------------------------");
       
       return Integer.parseInt(getStr("Type menu item, please")); 
   }
   
   public static String getStr(String s) throws Exception
   {
       System.out.println(s + ": ");
       return buf.readLine();
   }
   
   public static void Generate_ECDSA() throws Exception
   {
       String count = getStr("\nType number of participants(min = 2), please");
       
       try
    {
      Number = Integer.parseInt(count.trim());
    }
    catch (NumberFormatException nfe)
    {
      System.out.println("NumberFormatException: " + nfe.getMessage());
    }
       
    KeyPairGenerator kg = KeyPairGenerator.getInstance ("EC");
    kg.initialize (new ECGenParameterSpec("secp256k1")); 
    p = ((ECPublicKey) kg.generateKeyPair().getPublic()).getParams();
    G = p.getGenerator();
    
    String random_Ki = getStr("\nType random big number to generate private key, please");
    BigInteger o = new BigInteger(random_Ki);
    
    BigInteger[] Ki = SetRandomArray(o);
    Pi = SetECPointArray(Ki, G);
    
    BigInteger[] Ti = SetRandomArray(o);
    ECPoint[] Ri = SetECPointArray(Ti, G);

    ECPoint R = AddECPoints(Ri);
     
    e = R.getAffineX().mod(p.getOrder());
    String[] Str = Get_Text(Number);
    Hi = Get_Hash(Str);
    S = Add_BigInteger(SetArray_Si(Ti,Hi,Ki,e));
    System.out.println("ECDSA(s;e) = " + "(" + S + ";" + e + ")");
   }
   
   private static void Verify_ECDSA()
   {
    ECPoint[] HiPi = Get_HiPi(Pi,Hi);
    ECPoint P = AddECPoints(HiPi);
    ECPoint R2 = ScalarMultiply.addPoint(ScalarMultiply.scalmult(P, e), ScalarMultiply.scalmult(G, S));
    BigInteger A = R2.getAffineX().mod(p.getOrder());
    System.out.println("A = " + A);
    System.out.println("e = " + e);
    if(A.compareTo(e) == 0)
        System.out.println("SUCCESS: DS is valid!");
    else
        System.out.println("Fail: DS is not valid!");
   }
   
   private static ECPoint[] Get_HiPi(ECPoint[] pArray, BigInteger[] hArray)
   {
    ECPoint[] HiPi = new ECPoint[pArray.length];
    for(int i = 0; i < HiPi.length; i++)
    {
      HiPi[i] = ScalarMultiply.scalmult(pArray[i], hArray[i]);
    }
    return HiPi;
   }
   
   public static BigInteger[] Get_Hash(String[] str)
   {
       BigInteger[] Hi = new BigInteger[str.length];
       
       for(int i = 0; i<str.length; i++)
       {
           Hi[i] = new BigInteger(str[i].getBytes());
       }
       return Hi;
   }
   
    public static String[] Get_Text(int number) throws Exception
    {
        String[] array = new String[number];
        
        for(int i = 0; i<number; i++)
        {
            array[i] = getStr("Type your message, please, №" + i + ": ");
        }
        return array;
    }
   
    public static BigInteger randomLessThanN(BigInteger o) {
		BigInteger r;
		Random rnd = new Random();
		do {
                    r = new BigInteger(o.bitLength(), rnd);
		} while (r.compareTo(o) >= 0); 
		return r;
	}
      
    public static BigInteger set_s(BigInteger t, BigInteger e, BigInteger h, BigInteger k) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException
    {
        BigInteger s = t.subtract(e.multiply(k).multiply(h)).mod(p.getOrder());
        return s;
    }
    
    public static BigInteger[] SetArray_Si(BigInteger[] Ti, BigInteger[] Hi, BigInteger[] Ki, BigInteger e) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException
    {
        BigInteger[] Si = new BigInteger[Number];
        for(int i = 0; i < Si.length; i++)
        {
                Si[i] = Ti[i].subtract(e.multiply(Ki[i]).multiply(Hi[i])).mod(p.getOrder());
        }
        return Si;
    }
    
    public static BigInteger[] SetRandomArray(BigInteger o)
    {
        BigInteger[] Array = new BigInteger[Number];
        for(int i = 0; i < Array.length; i++)
        {
            Array[i] = randomLessThanN(o);
        }
        return Array;
    }
    
    public static ECPoint[] SetECPointArray(BigInteger[] array, ECPoint p)
    {
        ECPoint[] Array = new ECPoint[Number];
        for(int i = 0; i < Array.length; i++)
        {
            Array[i] = ScalarMultiply.scalmult(p, array[i]);
        }
        return Array;
    }
    
    public static ECPoint AddECPoints(ECPoint[] array)
    {
        int len = array.length;
        ECPoint point12 = ScalarMultiply.addPoint(array[len-1], array[len-2]);
        ECPoint Sum = point12;
        if(len > 2)
        {
            for(int i = len-3; i>=0; i--)
                Sum = ScalarMultiply.addPoint(Sum, array[i]);
        }
        return Sum;
    }
    
    public static BigInteger Add_BigInteger(BigInteger[] array) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException
    {
        int len = array.length;
        BigInteger BigInt12 = array[len-1].add(array[len-2]).mod(p.getOrder());
        BigInteger Sum = BigInt12;
        if(len > 2)
        {
            for(int i = len-3; i>=0; i--)
                Sum = Sum.add(array[i]).mod(p.getOrder());
        }
        return Sum;
    }
}
