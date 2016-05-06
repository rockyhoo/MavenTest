/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package com.hisen.DAO;

import org.springframework.jdbc.core.RowMapper;
import sun.security.provider.certpath.OCSP;
import sun.security.x509.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.TreeMap;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;

/**
 * Created by evilisn_jiang(evilisn_jiang@trendmicro.com.cn)) on 2016/4/25.
 */
public class CertMapper implements RowMapper {
    public static TreeMap<URI,X509Certificate> cached_issuers = new TreeMap<>();
    @Override
    public Object mapRow(ResultSet resultSet, int i) throws SQLException {
        Cert crt = new Cert();
        crt.setCertificate(resultSet.getString("certificate"));
        CertificateFactory fact = null;
        try {
            fact = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        X509Certificate x509cert = null;
        InputStream stream = new ByteArrayInputStream(crt.getCertificate().getBytes(StandardCharsets.UTF_8));
        try {
            x509cert = (X509Certificate) fact.generateCertificate(stream);
            crt.setClient_cert(x509cert);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        crt.setResponder_uri(OCSP.getResponderURI(x509cert));
        X509Certificate issuerCert;
        if (!cached_issuers.containsKey(getIssuerCertURL(x509cert))) {
            //download and set the issuers.
            try {
                issuerCert = getX509Certificate(httpGetBin(getIssuerCertURL(x509cert),true)) ;
                cached_issuers.put(getIssuerCertURL(x509cert),issuerCert);
                crt.setIssuer_cert(issuerCert);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }else{
            issuerCert = cached_issuers.get(getIssuerCertURL(x509cert));
            crt.setIssuer_cert(issuerCert);
        }




        Principal principal = x509cert.getIssuerDN();
        String issuerDn = principal.getName();
        crt.setIssuer_dn(issuerDn);
        return crt;
    }

    public static URI getIssuerCertURL(X509Certificate var0) {
        try {
            return getIssuerCertURL(X509CertImpl.toImpl(var0));
        } catch (CertificateException var2) {
            return null;
        }
    }

    static URI getIssuerCertURL(X509CertImpl var0) {
        AuthorityInfoAccessExtension var1 = var0.getAuthorityInfoAccessExtension();
        if(var1 == null) {
            return null;
        } else {
            List var2 = var1.getAccessDescriptions();
            Iterator var3 = var2.iterator();

            while(var3.hasNext()) {
                AccessDescription var4 = (AccessDescription)var3.next();
                if(var4.getAccessMethod().equals(AccessDescription.Ad_CAISSUERS_Id)) {
                    GeneralName var5 = var4.getAccessLocation();
                    if(var5.getType() == 6) {
                        URIName var6 = (URIName)var5.getName();
                        return var6.getURI();
                    }
                }
            }

            return null;
        }
    }
    public static byte[] httpGetBin(URI uri, boolean bActiveCheckUnknownHost) throws Exception

    {

        InputStream is = null;

        InputStream is_temp = null;

        try{

            if (uri == null) return null;

            URL url = uri.toURL();

            if(bActiveCheckUnknownHost){

                url.getProtocol();

                String host = url.getHost();

                int port = url.getPort();

                if(port == -1)

                    port = url.getDefaultPort();

                InetSocketAddress isa = new InetSocketAddress(host,port);

                if(isa.isUnresolved()){

                    //fix JNLP popup error issue

                    throw new UnknownHostException("Host Unknown:"+isa.toString());

                }

            }



            HttpURLConnection uc = (HttpURLConnection)url.openConnection();

            uc.setDoInput(true);

            uc.setAllowUserInteraction(false);

            uc.setInstanceFollowRedirects(true);

            setTimeout(uc);





            String contentEncoding = uc.getContentEncoding();

            int len = uc.getContentLength();



            // is = uc.getInputStream();

            if (contentEncoding != null && contentEncoding.toLowerCase().indexOf ("gzip") != -1)

            {

                is_temp = uc.getInputStream ();

                is = new GZIPInputStream(is_temp);

            }

            else if (contentEncoding != null && contentEncoding.toLowerCase().indexOf ("deflate") != -1)

            {

                is_temp = uc.getInputStream ();

                is = new InflaterInputStream(is_temp);

            }

            else

            {

                is = uc.getInputStream ();

            }



            if(len != -1){

                int ch = 0, i=0;

                byte[] res = new byte[len];

                while ( (ch = is.read()) != -1) {

                    res[i++] = (byte) (ch & 0xff);

                }



                return res;

            }else{

                ArrayList<byte[]> buffer = new ArrayList<byte[]>();

                int buf_len = 1024;

                byte[] res = new byte[buf_len];

                int ch = 0, i=0;

                while ( (ch = is.read()) != -1) {

                    res[i++] = (byte) (ch & 0xff);

                    if(i==buf_len){

                        //rotate

                        buffer.add(res);

                        i = 0;

                        res = new byte[buf_len];

                    }

                }



                int total_len = buffer.size() * buf_len + i;

                byte[] buf = new byte[total_len];

                for(int j=0; j<buffer.size();j++){

                    System.arraycopy(buffer.get(j), 0, buf, j*buf_len, buf_len);

                }

                if(i > 0){

                    System.arraycopy(res, 0, buf, buffer.size()*buf_len, i);

                }

                return buf;

            }

        }catch(Exception e){


            e.printStackTrace();

            return null;

        }finally{

            closeInputStream(is_temp);

            closeInputStream(is);

        }

    }
    private static void closeInputStream(InputStream is) {

        try {

            if (is != null)

                is.close();

        } catch (IOException e) {

            e.printStackTrace();

        }

    }

    private static void closeOutputStream(OutputStream out) {

        try {

            if (out != null)

                out.close();

        } catch (IOException e) {

            e.printStackTrace();

        }

    }
    static void setTimeout(URLConnection conn){

        conn.setConnectTimeout(10 * 1000);

        conn.setReadTimeout(10 * 1000);

    }
    public static X509Certificate getX509Certificate(byte[] bcert) throws CertificateException, IOException {
        if(bcert == null)
            return null;
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream bais = new ByteArrayInputStream(bcert);
        X509Certificate x509cert = (X509Certificate) cf
                .generateCertificate(bais);

        cf = null;
        bais.close();
        return x509cert;
    }
}