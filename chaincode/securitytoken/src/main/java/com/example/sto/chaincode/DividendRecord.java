package com.example.sto.chaincode;

import java.util.List;

public final class DividendRecord {
    private String dividendId;
    private long perTokenAmount;
    private long totalDistributed;
    private List<DividendEntry> entries;
    private long ts = System.currentTimeMillis();

    public DividendRecord() {}
    public DividendRecord(String dividendId, long perTokenAmount,
                          long totalDistributed, List<DividendEntry> entries) {
        this.dividendId = dividendId;
        this.perTokenAmount = perTokenAmount;
        this.totalDistributed = totalDistributed;
        this.entries = entries;
    }
    public String getDividendId() { return dividendId; }
    public long getPerTokenAmount() { return perTokenAmount; }
    public long getTotalDistributed() { return totalDistributed; }
    public List<DividendEntry> getEntries() { return entries; }
    public long getTs() { return ts; }

    public void setDividendId(String v) { this.dividendId = v; }
    public void setPerTokenAmount(long v) { this.perTokenAmount = v; }
    public void setTotalDistributed(long v) { this.totalDistributed = v; }
    public void setEntries(List<DividendEntry> v) { this.entries = v; }
    public void setTs(long v) { this.ts = v; }
}
