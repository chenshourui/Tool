package util;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.List;
import java.util.Map;


public class HttpService {
	
	//向指定URL发送GET方法请求，请求参数应该是 name1=value1&name2=value2 的形式
    public static String sendGet(String url, String param) {
        String result = "";
        BufferedReader in = null;
        try {
            String urlNameString = url + "?" + param;
            URL realUrl = new URL(urlNameString);
            // 打开和URL之间的连接
            URLConnection connection = realUrl.openConnection();
            // 设置通用的请求属性
            connection.setRequestProperty("accept", "*/*");
            connection.setRequestProperty("connection", "Keep-Alive");
            connection.setRequestProperty("user-agent","Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;SV1)");
            connection.setDoOutput(true);
            connection.setReadTimeout(60000);
            connection.setConnectTimeout(60000);
            connection.setDoInput(true);
            // 建立实际的连接
            connection.connect();
            // 获取所有响应头字段
            Map<String, List<String>> map = connection.getHeaderFields();
            // 遍历所有的响应头字段
            for (String key : map.keySet()) {
                System.out.println(key + "--->" + map.get(key));
            }
            // 定义 BufferedReader输入流来读取URL的响应
            in = new BufferedReader(new InputStreamReader(
                    connection.getInputStream()));
            String line;
            while ((line = in.readLine()) != null) {
                result += line;
            }
        } catch (Exception e) {
            System.out.println("发送GET请求出现异常！" + e);
            e.printStackTrace();
        }
        // 使用finally块来关闭输入流
        finally {
            try {
                if (in != null) {
                    in.close();
                }
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
        return result;
    }
    
    
    /**
     * 向指定 URL 发送POST方法的请求
     */
    public static String sendPost(String url, String param)throws Exception {
         
    	StringBuffer buffer = new StringBuffer();
		URL getUrl = new URL(url);
		HttpURLConnection connection = (HttpURLConnection)getUrl.openConnection();
		connection.setDoInput(true);
		connection.setDoOutput(true);
		connection.setRequestMethod("POST");
		connection.setRequestProperty("Content-Type", "application/xml");      //当传递from表单时，转换成application/form
		connection.setRequestProperty("Connection", "Keep-Alive"); 
		connection.setRequestProperty("变量名", "值");                         //设置头部信息
		connection.setUseCaches(false); 
		connection.setConnectTimeout(10000);
		
		connection.connect();
		OutputStreamWriter out = new OutputStreamWriter(connection.getOutputStream(), "UTF-8");
		out.write(param);
		out.flush();
		out.close();
		BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream(), "UTF-8"));
		String line = "";
		while ((line = reader.readLine()) != null) {
			buffer.append(line);
		}
		reader.close();
		return buffer.toString();
    
    }   
    
    
    //接收并相应请求
    //1、继承HttpServlet
    //2、get方法
			   /* public void doGet(HttpServletRequest request, HttpServletResponse response){
					response.setContentType("text/html; charset=UTF-8");
					PrintWriter writer =null ;
					try {
						writer = response.getWriter();
					} catch (IOException e) {
					
						e.printStackTrace();
					}	                                
					writer.write("get方法暂不支持");
					
				}*/
    //3、post方法
    /*
				public void doPost(HttpServletRequest request, HttpServletResponse response){
						response.setHeader("Cache-Control", "no-cache");
						response.setContentType("text/xml; charset=UTF-8");
						PrintWriter writer =null ;
						try {
							writer = response.getWriter();
						} catch (IOException e) {	
							e.printStackTrace();
						}
						
					    request.getHeader("变量名");                 //获取请求头
						request.getParameter("变量名");              //获取请求对应的变量值 
											
						final int bufferSize = 1024;
						final char[] buffer = new char[bufferSize];
						final StringBuilder out = new StringBuilder();
						try {
							InputStream inputStream = request.getInputStream();			
							
							Reader in = new InputStreamReader(inputStream, "UTF-8");
							for (; ; ) {
							    int rsz = in.read(buffer, 0, buffer.length);
							    if (rsz < 0)
							        break;
							    out.append(buffer, 0, rsz);
							}
						} catch (IOException e) {
							e.printStackTrace();
						}				
						String xml=out.toString();	
				
						writer.write(xml);  //响应请求					
					}
     */

}
