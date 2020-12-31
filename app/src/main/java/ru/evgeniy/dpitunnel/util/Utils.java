package ru.evgeniy.dpitunnel.util;

import android.util.Base64;
import android.util.Log;

import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.Proxy;
import java.net.URL;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;

import ru.evgeniy.dpitunnel.NoSSLv3SocketFactory;

public class Utils {

    public static String makeDOHRequest(String doh_server_url, String hostname)
    {
        String log_tag = "Java/Utils/makeDOHReqst";

        String response = "";
        try {
            // Create DNS request
            String hostname_full = hostname + '.'; // Dnsjava require dot at the end of hostname
            Message dns_message = Message.newQuery(Record.newRecord(new Name(hostname_full), Type.A, DClass.IN));

            // Encode DNS request to base64
            String dns_message_encoded = Base64.encodeToString(dns_message.toWire(), Base64.NO_PADDING);

            System.setProperty("http.keepAlive", "false");
            System.setProperty("java.net.preferIPv4Stack" , "true");

            // Proper process test.com and test.com/dns-query urls

            // Remove '/' if it exists on string end
            if(doh_server_url.charAt(doh_server_url.length() - 1) == '/') doh_server_url = doh_server_url.substring(0, doh_server_url.length() - 1);

            // Append request
            String url_str;
            if(doh_server_url.substring(doh_server_url.length() - 9).equals("dns-query"))
                url_str = doh_server_url + "?dns=" + dns_message_encoded;
            else
                url_str = doh_server_url + "/?dns=" + dns_message_encoded;

            URL url = new URL(url_str);
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection(Proxy.NO_PROXY);

            // Add header
            connection.setRequestProperty("accept", "application/dns-message");

            // Create the SSL connection
            connection.setSSLSocketFactory(new NoSSLv3SocketFactory());

            // Set options and connect
            connection.setReadTimeout(700);
            connection.setConnectTimeout(700);
            connection.setRequestMethod("GET");
            connection.setDoInput(true);

            // Save
            InputStream in = connection.getInputStream();

            ByteArrayOutputStream result = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int length;
            while ((length = in.read(buffer)) != -1) {
                result.write(buffer, 0, length);
            }

            Message dns_response = new Message(result.toByteArray());
            // Get list of RRset
            List<RRset> rrset_list = dns_response.getSectionRRsets(Section.ANSWER);
            // Try to find RRset with A type
            for (RRset rrset : rrset_list)
                if(rrset.getType() == Type.A){
                    // Get all A records
                    List<Record> records = rrset.rrs();
                    for(Record record : records) {
                        if(record.getName().equals(Name.fromString(hostname_full)))
                            response = record.rdataToString();
                    }

                    break;
                }

        } catch (Exception e) {
            Log.e(log_tag, "DoH request failed");
            e.printStackTrace();
        }

        return response;
    }
}
