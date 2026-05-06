package com.example.sto.service;

import com.example.sto.config.FabricConfig;
import io.grpc.ManagedChannel;
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.hyperledger.fabric.client.Contract;
import org.hyperledger.fabric.client.Gateway;
import org.hyperledger.fabric.client.Network;
import org.hyperledger.fabric.client.identity.Identities;
import org.hyperledger.fabric.client.identity.Identity;
import org.hyperledger.fabric.client.identity.Signer;
import org.hyperledger.fabric.client.identity.Signers;
import org.hyperledger.fabric.client.identity.X509Identity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

@ApplicationScoped
public class FabricGatewayService {

    private static final Logger log = LoggerFactory.getLogger(FabricGatewayService.class);

    @Inject FabricConfig cfg;

    private ManagedChannel channel;
    private Gateway gateway;
    private Contract contract;

    @PostConstruct
    public void init() {
        try {
            this.channel  = newGrpcChannel();
            Identity id   = newIdentity();
            Signer signer = newSigner();

            this.gateway = Gateway.newInstance()
                    .identity(id)
                    .signer(signer)
                    .connection(channel)
                    .evaluateOptions(o -> o.withDeadlineAfter(15, TimeUnit.SECONDS))
                    .endorseOptions(o -> o.withDeadlineAfter(30, TimeUnit.SECONDS))
                    .submitOptions(o -> o.withDeadlineAfter(30, TimeUnit.SECONDS))
                    .commitStatusOptions(o -> o.withDeadlineAfter(60, TimeUnit.SECONDS))
                    .connect();

            Network network = gateway.getNetwork(cfg.getChannel());
            this.contract = network.getContract(cfg.getChaincode());
            log.info("Fabric Gateway connected: channel={}, chaincode={}",
                    cfg.getChannel(), cfg.getChaincode());
        } catch (Exception e) {
            log.error("Fabric Gateway init failed", e);
            throw new RuntimeException(e);
        }
    }

    @PreDestroy
    public void shutdown() {
        try {
            if (gateway != null) gateway.close();
            if (channel != null) channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        } catch (Exception ignore) { }
    }

    public Contract contract() {
        return contract;
    }

    private ManagedChannel newGrpcChannel() throws Exception {
        var creds = GrpcSslContexts.forClient()
                .trustManager(Paths.get(cfg.getTlsCertPath()).toFile())
                .build();
        return NettyChannelBuilder.forTarget(cfg.getPeerEndpoint())
                .sslContext(creds)
                .overrideAuthority(cfg.getPeerHost())
                .build();
    }

    private Identity newIdentity() throws IOException, java.security.cert.CertificateException {
        try (var r = Files.newBufferedReader(Paths.get(cfg.getCertPath()))) {
            X509Certificate cert = Identities.readX509Certificate(r);
            return new X509Identity(cfg.getMspId(), cert);
        }
    }

    private Signer newSigner() throws IOException, java.security.GeneralSecurityException {
        Path keyDir = Paths.get(cfg.getKeyDir());
        try (Stream<Path> files = Files.list(keyDir)) {
            Path keyFile = files.findFirst()
                    .orElseThrow(() -> new IOException("no key file in " + keyDir));
            try (var r = Files.newBufferedReader(keyFile)) {
                PrivateKey pk = Identities.readPrivateKey(r);
                return Signers.newPrivateKeySigner(pk);
            }
        }
    }
}
