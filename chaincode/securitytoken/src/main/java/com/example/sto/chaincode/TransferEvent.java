package com.example.sto.chaincode;

public final class TransferEvent {
    private String from;
    private String to;
    private long amount;
    private long ts = System.currentTimeMillis();

    public TransferEvent() {}
    public TransferEvent(String from, String to, long amount) {
        this.from = from; this.to = to; this.amount = amount;
    }

    public String getFrom() { return from; }
    public String getTo() { return to; }
    public long getAmount() { return amount; }
    public long getTs() { return ts; }
    public void setFrom(String v) { this.from = v; }
    public void setTo(String v) { this.to = v; }
    public void setAmount(long v) { this.amount = v; }
    public void setTs(long v) { this.ts = v; }
}
