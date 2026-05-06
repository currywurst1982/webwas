package com.example.sto.config;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class FabricConfig {

    private final String mspId       = env("FABRIC_MSP_ID",        "Org1MSP");
    private final String channel     = env("FABRIC_CHANNEL",       "stochannel");
    private final String chaincode   = env("FABRIC_CHAINCODE",     "securitytoken");
    private final String peerEndpoint= env("FABRIC_PEER_ENDPOINT", "localhost:7051");
    private final String peerHost    = env("FABRIC_PEER_HOST",     "peer0.org1.example.com");
    private final String tlsCertPath = env("FABRIC_TLS_CERT",
            "/opt/fabric/crypto/peerOrganizations/org1.example.com/peers/"
            + "peer0.org1.example.com/tls/ca.crt");
    private final String certPath    = env("FABRIC_USER_CERT",
            "/opt/fabric/crypto/peerOrganizations/org1.example.com/users/"
            + "Admin@org1.example.com/msp/signcerts/cert.pem");
    private final String keyDir      = env("FABRIC_USER_KEY_DIR",
            "/opt/fabric/crypto/peerOrganizations/org1.example.com/users/"
            + "Admin@org1.example.com/msp/keystore");

    private static String env(String key, String def) {
        String v = System.getenv(key);
        return (v == null || v.isBlank()) ? def : v;
    }

    public String getMspId()       { return mspId; }
    public String getChannel()     { return channel; }
    public String getChaincode()   { return chaincode; }
    public String getPeerEndpoint(){ return peerEndpoint; }
    public String getPeerHost()    { return peerHost; }
    public String getTlsCertPath() { return tlsCertPath; }
    public String getCertPath()    { return certPath; }
    public String getKeyDir()      { return keyDir; }
}
