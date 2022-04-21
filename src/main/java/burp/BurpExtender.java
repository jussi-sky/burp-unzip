package burp;

import java.io.*;
import java.net.URLDecoder;
import java.util.Base64;
import java.util.List;
import java.util.zip.GZIPInputStream;

public class BurpExtender implements IBurpExtender, IHttpListener {

    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        callbacks.setExtensionName("Unzip From Base64");
        helpers = callbacks.getHelpers();
        callbacks.registerHttpListener(this);
        callbacks.printOutput("Load Success !!!");
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {

        String sensorsdataHost = "fordcarproduction.datasink.sensorsdata.cn";

        // only process requests
        if (messageIsRequest) {

            byte[] request = messageInfo.getRequest();
            IRequestInfo analyzeRequest = helpers.analyzeRequest(request);
            List<IParameter> paraList = analyzeRequest.getParameters();
            IHttpService httpService = messageInfo.getHttpService();

            if (!sensorsdataHost.equalsIgnoreCase(httpService.getHost())){
                return;
            }

            for (IParameter para : paraList){
                String key = para.getName();
                String value = para.getValue();
                int type = para.getType();
                if ("data_list".equals(key)){
                    String zip_data = null;
                    String data = null;
                    try {
                        stdout.println("Host:" + httpService.getHost());
                        zip_data = URLDecoder.decode(value,"UTF-8");
                        data = DecompressFromBase64(zip_data);
                        stdout.println(data + "\n");
                    } catch (UnsupportedEncodingException e) {
                        e.printStackTrace();
                    }

                }
            }
        }
    }

    /**
     * 把数据包里 base64编码 的 gzip 数据转换为 string
     * @param base64ToDecode 待解压的 base64 数据
     * @return
     */
    public static String DecompressFromBase64(String base64ToDecode){
        
        try {
            byte[] compressed = Base64.getDecoder().decode(base64ToDecode);
            final int BUFFER_SIZE = 32;
            ByteArrayInputStream inputStream = new ByteArrayInputStream(compressed);

            GZIPInputStream gis  = new GZIPInputStream(inputStream, BUFFER_SIZE);
            
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] data = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = gis.read(data)) != -1) {
                baos.write(data, 0, bytesRead);
            }
            return baos.toString("UTF-8");

        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

}
