package com.example.sto.chaincode;

public final class DividendEntry {
    private String investorId;
    private long payout;

    public DividendEntry() {}
    public DividendEntry(String investorId, long payout) {
        this.investorId = investorId;
        this.payout = payout;
    }
    public String getInvestorId() { return investorId; }
    public long getPayout() { return payout; }
    public void setInvestorId(String v) { this.investorId = v; }
    public void setPayout(long v) { this.payout = v; }
}
