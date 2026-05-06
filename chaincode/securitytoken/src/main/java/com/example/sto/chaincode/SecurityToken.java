package com.example.sto.chaincode;

import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;

@DataType
public final class SecurityToken {

    @Property
    private String symbol;

    @Property
    private String name;

    @Property
    private String issuer;

    @Property
    private long totalSupply;

    @Property
    private int decimals;

    @Property
    private boolean paused;

    public SecurityToken() {}

    public SecurityToken(String symbol, String name, String issuer,
                         long totalSupply, int decimals, boolean paused) {
        this.symbol = symbol;
        this.name = name;
        this.issuer = issuer;
        this.totalSupply = totalSupply;
        this.decimals = decimals;
        this.paused = paused;
    }

    public String getSymbol() { return symbol; }
    public String getName() { return name; }
    public String getIssuer() { return issuer; }
    public long getTotalSupply() { return totalSupply; }
    public int getDecimals() { return decimals; }
    public boolean isPaused() { return paused; }

    public void setSymbol(String v) { this.symbol = v; }
    public void setName(String v) { this.name = v; }
    public void setIssuer(String v) { this.issuer = v; }
    public void setTotalSupply(long v) { this.totalSupply = v; }
    public void setDecimals(int v) { this.decimals = v; }
    public void setPaused(boolean v) { this.paused = v; }
}
