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

import java.net.URI;
import java.net.URL;
import java.security.cert.X509Certificate;

/**
 * Created by evilisn_jiang(evilisn_jiang@trendmicro.com.cn)) on 2016/4/25.
 */
public class Cert {

    private String certificate;
    private String cn;
    private String issuer_dn;
    private URL ocsp_url;
    private X509Certificate issuer_cert;
    private X509Certificate client_cert;
    private URI responder_uri;

    public URI getResponder_uri() {
        return responder_uri;
    }

    public void setResponder_uri(URI responder_uri) {
        this.responder_uri = responder_uri;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    public String getCertificate() {
        return certificate;
    }

    public void setIssuer_dn(String issuer_dn) {
        this.issuer_dn = issuer_dn;
    }

    public void setCn(String cn) {
        this.cn = cn;
    }

    public void setOcsp_url(URL ocsp_url) {
        this.ocsp_url = ocsp_url;
    }

    public String getIssuer_dn() {
        return issuer_dn;
    }

    public void setIssuer_cert(X509Certificate issuer_cert) {
        this.issuer_cert = issuer_cert;
    }

    public void setClient_cert(X509Certificate client_cert) {
        this.client_cert = client_cert;
    }

    public String getCn() {
        return cn;
    }

    public URL getOcsp_url() {
        return ocsp_url;
    }

    public X509Certificate getIssuer_cert() {
        return issuer_cert;
    }

    public X509Certificate getClient_cert() {
        return client_cert;
    }
}
