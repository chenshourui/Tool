package util.aes;

import java.io.IOException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.zip.CRC32;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/*
一、概述
	接口对公网暴露。这就可能会带来潜在的风险，诸如客户信息泄露、商品信息、价格信息泄露等等。
	随着供应链项目的发展壮大，为了防范于未然，现拟定接口通信加密的约定，并在双方开发完成后，统一上线部署

二、环境与术语定义
	基础通信协议 - HTTP
	明文 - 加密前/解密后的数据内容
	密文 - 加密后的数据内容
	私钥 - 加/解密时使用的、不能公开的内容，由加/解密双方保存在安全的位置
	IV向量 - 用于参与加密时，作为初始种子使用的一组数据，与私钥不同的是，其可以公开
	校验 - CRC32 校验值
	HTTP 报头 - HTTP 协议中的 Header
	报文 - 解密后的格式化的接口通信数据明文
二、加密算法实现
	加密使用 rijndael-128 算法 （即 AES），CBC 模式。其中数据填充处理，采用 PKCS#5 算法
	注意，在此模式下，私钥的长度不得少于 16 位，否则安全性无法保证
	为了简化开发，
	以下采用伪代码描述加密过程
	设 （以下内容均不含单引号）：
	给定 字符串 S 为 'scm-wms-encryption-secret'，明文 P 为 'test'，IV向量采用安全随机生成，注意必须是安全随机，不要使用普通随机数生成器例如 Random 等
	私钥 K 为 SUBSTR ( S, GET_KEY_SIZE () )
	其中 GET_KEY_SIZE 为 rijndael-128 CBC 模式下的私钥最大长度
	GET_IV_SIZE 为相同模式下 IV 的长度
	有：
	K = SUBSTR ( S, GET_KEY_SIZE () )
	IV = SECURE_RANDOM()
	RIJNDAEL128_INIT( K, IV )
	DAT = PKCS5_PADDING ( P )
	ENC = RIJNDAEL128 ( DAT )
	OUT = BASE64_ENCODE ( IV + ENC )
	也就是说，加密以后的密文最前面附加了 IV 后面紧跟密文 （IV 暴露不影响安全），同时我们需要使用 base64 再进行一次编码，便于使用基础通信协议进行传输
三、密钥轮换
	为了进一步加强加密安全性，密钥采用定期轮换。这样可以加大攻击者的攻击难度。因为在双方通信过程中，我们必须采用一个可变化的，且双方都已知的常量，作为索引，去“轮转”选择密钥
	常用算法采用当前时间，取作索引。但是，由于网络传输延迟、系统时间差异等，会造成一个“漂移”现象。可能会导致双方加解密失败。
	例如，请求由 A 系统向 B 系统发起（假设双方系统时间准确），A 系统发起请求的时间为 11时59分59秒750毫秒，此时对应的密钥为 'ABC'。由于网络传输耗时，B 系统收到并处理此数据时，时间已是12时00分00秒001毫秒
	此时对应的密钥为 'DEF'，此刻 B 系统中，解密就会失败，A 系统不得不重新发起请求（重试）。这样，系统复杂度会大大上升。
	解决这种时间“漂移”的做法是，请求方提供时间。即 A 请求 B 时，携带系统当前时间。采用 HTTP Date: 报头指定用作发起请求时，取密钥索引的时间
	为了简化开发，密钥轮换算法采用当前时间中 分 作为索引，则有 0...59 共计 60 组。
	例如当前时间为 12:34:56 则索引为 34
	 双方各维护共计 60 个密钥的密码本（不要放到配置文件中），即可
四、数据校验
	由于基础通信协议传输的不确定性，密文可能存在损坏的风险，因此，需要对加密后的密文计算出一个校验值 C
	其算法采用 CRC32，即 C = CRC32( OUT )
	然后使用 X-Request-Valid: 报头 传递
	例如：
	X-Request-Valid: 7d313198
五、基础通信协议的请求构造
	在请求时，必须携带数据校验报头，并将密文作为请求的 BODY 传输（除了密文以外，不得再传输其他内容）
	请求内容编码采用 UTF-8
六、可选加密
	为了便于开发时报文传输调试、和大请求量下CPU减负，加密应该是可选的。
	默认情况下，一直为开启状态，当请求中含有 X-Requested-With: 报头不为空时，则关闭加密，使用明文传输
 */
public class AES {

	final String KEY_ALGORITHM = "AES";	// 算法
	final String algorithmStr = "AES/CBC/PKCS5Padding";  // 填充类型（"算法/模式/补码方式"）
	
	private Key key;
	private Cipher cipher;
	static int ivLength=0;    //iv向量的长度
	
	/**
	 * 加密和解密前的初始化
	 */
	public void init(byte[] keyBytes) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		 //密匙不足16位，补足16位
		 int base = 16;
		 if (keyBytes.length % base != 0) {
			 int groups = keyBytes.length / base + (keyBytes.length % base != 0 ? 1 : 0);
			 byte[] temp = new byte[groups * base];
			 Arrays.fill(temp, (byte) 0);
			 System.arraycopy(keyBytes, 0, temp, 0, keyBytes.length);
			 keyBytes = temp;
		 }
		  
		 //加入bouncyCastle支持 
		 Security.addProvider(new BouncyCastleProvider()); 
		 // 转化成JAVA的密钥格式  
		 key = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
		 //初始化cipher
		 cipher = Cipher.getInstance(algorithmStr, "BC");
		 //获取iv向量长度
		 ivLength=cipher.getBlockSize();
	}
	
	
	 /**
	  * 加密 
	  */
	 public byte[]  encrypt(byte[] content, byte[] keyBytes) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		 byte[] encryptedText = null;
		 init(keyBytes);
		 
		 byte[] iv=new byte[ivLength];              //定义iv向量
		 SecureRandom random = new SecureRandom();  //SecureRandom用于自动生成iv向量
		 random.nextBytes(iv);
		 
		 try {
			 cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
			 encryptedText = cipher.doFinal(content);
		 } catch (Exception e) {
			 e.printStackTrace();
		 }
		 byte[] result = new byte[ivLength+encryptedText.length];                //将iv和加密后的内容拼接，返回（用于base64加密）	  
		 System.arraycopy(iv, 0, result, 0, ivLength);
		 System.arraycopy(encryptedText, 0, result, ivLength, encryptedText.length);
	  
		 return result;
	 }
	 
	 /**
	  *解密
	  */
	 public byte[] decrypt(byte[] encryptedData, byte[] keyBytes) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		 byte[] encryptedText = null;
		 init(keyBytes);
		//将获取的密文，分离成iv和对应的内容
		 byte[] iv=new byte[ivLength];                      
		 byte[] data=new byte[encryptedData.length-16];   	  
		 System.arraycopy(encryptedData, 0, iv, 0, 16);
		 System.arraycopy(encryptedData, ivLength, data, 0, encryptedData.length-ivLength);
	 
		 try {
			 cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
			 encryptedText = cipher.doFinal(data);
		 } catch (Exception e) {
			 e.printStackTrace();
		 }
		 return encryptedText;
	 }
	 
	 //加入时间，进行动态key解密
	public String ScmDec(String content,String strDate) throws ParseException, IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException{
		 
		 SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		 Date date = sdf.parse(strDate);		 
		 Calendar calendar = Calendar.getInstance();
		 calendar.setTime(date);
		 int minute= calendar.get(Calendar.MINUTE);
		 byte[] keybytes =StaticConstant.keyList[minute].getBytes("UTF-8");
		 
		 byte[] con =new sun.misc.BASE64Decoder().decodeBuffer(content);
		 byte[] dec = decrypt(con, keybytes);
		 
		 return  new String(dec,"UTF-8");
	 }
	 
	 //加入时间，进行动态key加密
	 public String ScmEnc(String content,String strDate) throws ParseException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException{
		 SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		 Date date = sdf.parse(strDate);		 
		 Calendar calendar = Calendar.getInstance();
		 calendar.setTime(date);
		 int minute= calendar.get(Calendar.MINUTE);
		 byte[] keybytes =StaticConstant.keyList[minute].getBytes("UTF-8");
		 byte[] enc = encrypt(content.getBytes("UTF-8"), keybytes);
		 
		 return  new sun.misc.BASE64Encoder().encode(enc);
	 }
	 
	 public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, ParseException {
		 AES aes = new AES();
		 
//		 SimpleDateFormat sdf = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss 'GMT'", Locale.US);
//		    Date dateTemp = null;
//			try {
//				dateTemp = sdf.parse("Tue, 18 Oct 2016 14:12:37 +0000");
//			} catch (ParseException e1) {
//
//			}
//			sdf=new SimpleDateFormat("yyyy-MM-dd HH:mm:ss"); 
//		 
//	
//		 Date date = sdf.parse(sdf.format(dateTemp));		 
//		 Calendar calendar = Calendar.getInstance();
//		 calendar.setTime(date);
//		 int minute= calendar.get(Calendar.MINUTE);
//		 
//		 System.out.println(minute);
		 System.out.println(StaticConstant.keyList[12]);
		 
		 byte[] keybytes = StaticConstant.keyList[12].getBytes("UTF-8");//定义密匙

		 
		 String content = "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";
//		 System.out.println();
//		 System.out.println("-------------加密---------------");
//		 byte[] enc = aes.encrypt(content.getBytes(), keybytes);	 
//		 String base= new sun.misc.BASE64Encoder().encode(enc);
//		 System.out.println(base);
//		 
		 System.out.println();
		 System.out.println("---------------解密--------------");
		 byte[] con =new sun.misc.BASE64Decoder().decodeBuffer(content);	
		 byte[] dec = aes.decrypt(con, keybytes);
		 System.out.println( new String(dec));
//		 System.out.println();
		 
		  System.out.println("---------------CRC32(用于验证是否对包)--------------");
		  CRC32 crc32 = new CRC32();
		  crc32.update("KM2Crw++T+pRfGr0xgnUiA==".getBytes());
		  System.out.println(crc32.getValue());
	 }
	

}
