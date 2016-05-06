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
package com.hisen;

import com.hisen.DAO.Cert;
import com.hisen.DAO.CertMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import sun.security.provider.certpath.OCSP;

import java.io.IOException;
import java.security.cert.CertPathValidatorException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Created by evilisn_jiang(evilisn_jiang@trendmicro.com.cn)) on 2016/4/10.
 */
@EnableAutoConfiguration
@Component
public class ScheduledTasks {
    @Autowired
    JdbcTemplate jdbcTemplate;

    private static final Logger log = LoggerFactory.getLogger(ScheduledTasks.class);


    @Scheduled(fixedRate = 10*60000)
    public void scheduledCheckOCSP() throws InterruptedException {
        log.info("fetching certs");
        ArrayList<Cert> certs= (ArrayList<Cert>) getCerts();
        log.info(String.format("[%d] certs to be checked.", certs.size()));

        Date now= new Date();
        long startTime = now.getTime();
        System.setProperty("java.util.concurrent.ForkJoinPool.common.parallelism", "50");
        AtomicInteger c_REVOKED=new AtomicInteger();
        AtomicInteger c_GOOD=new AtomicInteger();
        AtomicInteger c_UNKNOWN=new AtomicInteger();
        AtomicInteger c_VALID=new AtomicInteger();
        AtomicInteger c_EXPIRED=new AtomicInteger();

        certs.parallelStream().forEach(o -> {
            try {
                if (o.getClient_cert().getNotAfter().after(now)) {
                    OCSP.RevocationStatus.CertStatus resp=OCSP.check(o.getClient_cert(), o.getIssuer_cert()).getCertStatus();
                    log.info(String.format("Serial Number [%20s]| OCSP Status:[%s]",
                            o.getClient_cert().getSerialNumber(),
                            resp.toString()));
                    c_VALID.getAndIncrement();
                    if(resp==OCSP.RevocationStatus.CertStatus.GOOD) c_GOOD.getAndIncrement();
                    if(resp==OCSP.RevocationStatus.CertStatus.UNKNOWN) c_UNKNOWN.getAndIncrement();
                    if(resp==OCSP.RevocationStatus.CertStatus.REVOKED) c_REVOKED.getAndIncrement();
                }else{
                    //expired.
                    c_EXPIRED.getAndIncrement();
                }
            } catch (IOException e) {
                e.printStackTrace();
            } catch (CertPathValidatorException e) {
                e.printStackTrace();
            }
        });
        long endTime = System.currentTimeMillis();
        log.info("ALL "+certs.size()+" certificates processed in "+(endTime - startTime) /100+" seconds, with "+c_VALID.get()+" valid certs, "+c_EXPIRED+" expired certs, among which "+ c_GOOD.get()+ " is GOOD, "+c_REVOKED.get()+" is revoked, and "+
        c_UNKNOWN.get()+" is KNOWN.");
    }



    private List<Cert> getCerts() {
        final String SQL = "SELECT * FROM certificate order by id desc";
        List<Cert> certs = jdbcTemplate.query(SQL, new CertMapper());
        return certs;
    }


    class MyThread extends Thread
    {
        private ArrayList<Cert> certs;
        private int startIdx, nThreads, maxIdx;

        public MyThread(int s, int n, int m, ArrayList<Cert> certList)
        {
            this.startIdx = s;
            this.nThreads = n;
            this.maxIdx = m;
            this.certs=certList;
        }

        @Override
        public void run()
        {
            for(int i = this.startIdx; i < this.maxIdx; i += this.nThreads)
            {
                System.out.println("[ID " + this.getId() + "] " + i);
            }
        }
    }

}
