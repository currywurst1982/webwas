package com.example.sto.service;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.hyperledger.fabric.client.Contract;

import java.nio.charset.StandardCharsets;

@ApplicationScoped
public class SecurityTokenService {

    @Inject FabricGatewayService gw;

    public String initToken(String symbol, String name, int decimals) throws Exception {
        Contract c = gw.contract();
        byte[] r = c.submitTransaction("initToken", symbol, name, String.valueOf(decimals));
        return new String(r, StandardCharsets.UTF_8);
    }

    public String getToken() throws Exception {
        return new String(gw.contract().evaluateTransaction("getToken"),
                StandardCharsets.UTF_8);
    }

    public String registerHolder(String investorId, boolean kyc, String country)
            throws Exception {
        return new String(gw.contract().submitTransaction("registerHolder",
                investorId, String.valueOf(kyc), country), StandardCharsets.UTF_8);
    }

    public String updateKyc(String investorId, boolean kyc) throws Exception {
        return new String(gw.contract().submitTransaction("updateKyc",
                investorId, String.valueOf(kyc)), StandardCharsets.UTF_8);
    }

    public String issue(String investorId, long amount) throws Exception {
        return new String(gw.contract().submitTransaction("issue",
                investorId, String.valueOf(amount)), StandardCharsets.UTF_8);
    }

    public String transfer(String fromId, String toId, long amount) throws Exception {
        return new String(gw.contract().submitTransaction("transfer",
                fromId, toId, String.valueOf(amount)), StandardCharsets.UTF_8);
    }

    public String burn(String investorId, long amount) throws Exception {
        return new String(gw.contract().submitTransaction("burn",
                investorId, String.valueOf(amount)), StandardCharsets.UTF_8);
    }

    public String lock(String investorId, long amount) throws Exception {
        return new String(gw.contract().submitTransaction("lock",
                investorId, String.valueOf(amount)), StandardCharsets.UTF_8);
    }

    public String unlock(String investorId, long amount) throws Exception {
        return new String(gw.contract().submitTransaction("unlock",
                investorId, String.valueOf(amount)), StandardCharsets.UTF_8);
    }

    public String pause(boolean paused) throws Exception {
        return new String(gw.contract().submitTransaction("pause",
                String.valueOf(paused)), StandardCharsets.UTF_8);
    }

    public String distributeDividend(String dividendId, long perTokenAmount)
            throws Exception {
        return new String(gw.contract().submitTransaction("distributeDividend",
                dividendId, String.valueOf(perTokenAmount)), StandardCharsets.UTF_8);
    }

    public String getHolder(String investorId) throws Exception {
        return new String(gw.contract().evaluateTransaction("getHolder", investorId),
                StandardCharsets.UTF_8);
    }

    public String listHolders() throws Exception {
        return new String(gw.contract().evaluateTransaction("listHolders"),
                StandardCharsets.UTF_8);
    }
}
