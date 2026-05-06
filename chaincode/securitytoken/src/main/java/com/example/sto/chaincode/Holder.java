package com.example.sto.chaincode;

import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;

@DataType
public final class Holder {

    @Property
    private String investorId;

    @Property
    private long balance;

    @Property
    private long lockedBalance;

    @Property
    private boolean kycVerified;

    @Property
    private String country;

    public Holder() {}

    public Holder(String investorId, long balance, long lockedBalance,
                  boolean kycVerified, String country) {
        this.investorId = investorId;
        this.balance = balance;
        this.lockedBalance = lockedBalance;
        this.kycVerified = kycVerified;
        this.country = country;
    }

    public String getInvestorId() { return investorId; }
    public long getBalance() { return balance; }
    public long getLockedBalance() { return lockedBalance; }
    public boolean isKycVerified() { return kycVerified; }
    public String getCountry() { return country; }

    public void setInvestorId(String v) { this.investorId = v; }
    public void setBalance(long v) { this.balance = v; }
    public void setLockedBalance(long v) { this.lockedBalance = v; }
    public void setKycVerified(boolean v) { this.kycVerified = v; }
    public void setCountry(String v) { this.country = v; }

    public long getAvailableBalance() {
        return balance - lockedBalance;
    }
}
