package com.example.sto.chaincode;

import com.owlike.genson.Genson;
import org.hyperledger.fabric.contract.Context;
import org.hyperledger.fabric.contract.ContractInterface;
import org.hyperledger.fabric.contract.annotation.Contact;
import org.hyperledger.fabric.contract.annotation.Contract;
import org.hyperledger.fabric.contract.annotation.Default;
import org.hyperledger.fabric.contract.annotation.Info;
import org.hyperledger.fabric.contract.annotation.License;
import org.hyperledger.fabric.contract.annotation.Transaction;
import org.hyperledger.fabric.shim.ChaincodeException;
import org.hyperledger.fabric.shim.ChaincodeStub;
import org.hyperledger.fabric.shim.ledger.KeyValue;
import org.hyperledger.fabric.shim.ledger.QueryResultsIterator;

import java.util.ArrayList;
import java.util.List;

@Contract(
    name = "SecurityTokenContract",
    info = @Info(
        title = "Security Token Contract",
        description = "Tokenized securities (STO) reference contract",
        version = "1.0.0",
        license = @License(name = "Apache-2.0"),
        contact = @Contact(email = "sto@example.com", name = "STO Team")))
@Default
public final class SecurityTokenContract implements ContractInterface {

    private static final String TOKEN_KEY = "TOKEN_META";
    private static final String HOLDER_PREFIX = "HOLDER_";
    private static final String DIVIDEND_PREFIX = "DIV_";
    private final Genson genson = new Genson();

    private enum Err {
        NOT_INITIALIZED, ALREADY_INITIALIZED, NOT_ISSUER, PAUSED,
        HOLDER_NOT_FOUND, KYC_REQUIRED, INSUFFICIENT_BALANCE,
        INVALID_AMOUNT, COUNTRY_NOT_ALLOWED
    }

    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public SecurityToken initToken(final Context ctx,
                                   final String symbol,
                                   final String name,
                                   final int decimals) {
        ChaincodeStub stub = ctx.getStub();
        if (stub.getState(TOKEN_KEY).length > 0) {
            throw new ChaincodeException("token already initialized",
                    Err.ALREADY_INITIALIZED.name());
        }
        String issuer = ctx.getClientIdentity().getMSPID();
        SecurityToken token = new SecurityToken(symbol, name, issuer, 0L, decimals, false);
        stub.putState(TOKEN_KEY, genson.serializeBytes(token));
        return token;
    }

    @Transaction(intent = Transaction.TYPE.EVALUATE)
    public SecurityToken getToken(final Context ctx) {
        return loadToken(ctx);
    }

    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public Holder registerHolder(final Context ctx,
                                 final String investorId,
                                 final boolean kycVerified,
                                 final String country) {
        requireIssuer(ctx);
        ChaincodeStub stub = ctx.getStub();
        String key = HOLDER_PREFIX + investorId;
        if (stub.getState(key).length > 0) {
            return genson.deserialize(stub.getState(key), Holder.class);
        }
        Holder h = new Holder(investorId, 0L, 0L, kycVerified, country);
        stub.putState(key, genson.serializeBytes(h));
        return h;
    }

    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public Holder updateKyc(final Context ctx,
                            final String investorId,
                            final boolean kycVerified) {
        requireIssuer(ctx);
        Holder h = loadHolder(ctx, investorId);
        h.setKycVerified(kycVerified);
        ctx.getStub().putState(HOLDER_PREFIX + investorId, genson.serializeBytes(h));
        return h;
    }

    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public SecurityToken issue(final Context ctx,
                               final String investorId,
                               final long amount) {
        requireIssuer(ctx);
        requirePositive(amount);
        SecurityToken token = loadToken(ctx);
        if (token.isPaused()) {
            throw new ChaincodeException("token paused", Err.PAUSED.name());
        }
        Holder h = loadHolder(ctx, investorId);
        if (!h.isKycVerified()) {
            throw new ChaincodeException("investor not KYC-verified",
                    Err.KYC_REQUIRED.name());
        }
        h.setBalance(h.getBalance() + amount);
        token.setTotalSupply(token.getTotalSupply() + amount);

        ChaincodeStub stub = ctx.getStub();
        stub.putState(HOLDER_PREFIX + investorId, genson.serializeBytes(h));
        stub.putState(TOKEN_KEY, genson.serializeBytes(token));
        stub.setEvent("TokensIssued",
                genson.serializeBytes(new TransferEvent("ISSUER", investorId, amount)));
        return token;
    }

    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public Holder transfer(final Context ctx,
                           final String fromId,
                           final String toId,
                           final long amount) {
        requirePositive(amount);
        SecurityToken token = loadToken(ctx);
        if (token.isPaused()) {
            throw new ChaincodeException("token paused", Err.PAUSED.name());
        }
        Holder from = loadHolder(ctx, fromId);
        Holder to = loadHolder(ctx, toId);
        if (!from.isKycVerified() || !to.isKycVerified()) {
            throw new ChaincodeException("KYC required for both parties",
                    Err.KYC_REQUIRED.name());
        }
        if (from.getAvailableBalance() < amount) {
            throw new ChaincodeException("insufficient available balance",
                    Err.INSUFFICIENT_BALANCE.name());
        }
        if (isRestrictedCountry(to.getCountry())) {
            throw new ChaincodeException("destination country not allowed",
                    Err.COUNTRY_NOT_ALLOWED.name());
        }
        from.setBalance(from.getBalance() - amount);
        to.setBalance(to.getBalance() + amount);

        ChaincodeStub stub = ctx.getStub();
        stub.putState(HOLDER_PREFIX + fromId, genson.serializeBytes(from));
        stub.putState(HOLDER_PREFIX + toId, genson.serializeBytes(to));
        stub.setEvent("TokensTransferred",
                genson.serializeBytes(new TransferEvent(fromId, toId, amount)));
        return to;
    }

    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public Holder lock(final Context ctx,
                       final String investorId,
                       final long amount) {
        requireIssuer(ctx);
        requirePositive(amount);
        Holder h = loadHolder(ctx, investorId);
        if (h.getAvailableBalance() < amount) {
            throw new ChaincodeException("insufficient balance to lock",
                    Err.INSUFFICIENT_BALANCE.name());
        }
        h.setLockedBalance(h.getLockedBalance() + amount);
        ctx.getStub().putState(HOLDER_PREFIX + investorId, genson.serializeBytes(h));
        return h;
    }

    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public Holder unlock(final Context ctx,
                         final String investorId,
                         final long amount) {
        requireIssuer(ctx);
        requirePositive(amount);
        Holder h = loadHolder(ctx, investorId);
        if (h.getLockedBalance() < amount) {
            throw new ChaincodeException("insufficient locked balance",
                    Err.INSUFFICIENT_BALANCE.name());
        }
        h.setLockedBalance(h.getLockedBalance() - amount);
        ctx.getStub().putState(HOLDER_PREFIX + investorId, genson.serializeBytes(h));
        return h;
    }

    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public SecurityToken pause(final Context ctx, final boolean paused) {
        requireIssuer(ctx);
        SecurityToken t = loadToken(ctx);
        t.setPaused(paused);
        ctx.getStub().putState(TOKEN_KEY, genson.serializeBytes(t));
        return t;
    }

    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public SecurityToken burn(final Context ctx,
                              final String investorId,
                              final long amount) {
        requireIssuer(ctx);
        requirePositive(amount);
        SecurityToken token = loadToken(ctx);
        Holder h = loadHolder(ctx, investorId);
        if (h.getAvailableBalance() < amount) {
            throw new ChaincodeException("insufficient balance to burn",
                    Err.INSUFFICIENT_BALANCE.name());
        }
        h.setBalance(h.getBalance() - amount);
        token.setTotalSupply(token.getTotalSupply() - amount);

        ChaincodeStub stub = ctx.getStub();
        stub.putState(HOLDER_PREFIX + investorId, genson.serializeBytes(h));
        stub.putState(TOKEN_KEY, genson.serializeBytes(token));
        stub.setEvent("TokensBurned",
                genson.serializeBytes(new TransferEvent(investorId, "BURN", amount)));
        return token;
    }

    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public String distributeDividend(final Context ctx,
                                     final String dividendId,
                                     final long perTokenAmount) {
        requireIssuer(ctx);
        requirePositive(perTokenAmount);
        ChaincodeStub stub = ctx.getStub();
        long totalDistributed = 0L;
        List<DividendEntry> entries = new ArrayList<>();

        try (QueryResultsIterator<KeyValue> it = stub.getStateByRange(
                HOLDER_PREFIX, HOLDER_PREFIX + "￿")) {
            for (KeyValue kv : it) {
                Holder h = genson.deserialize(kv.getValue(), Holder.class);
                long payout = h.getBalance() * perTokenAmount;
                if (payout > 0) {
                    entries.add(new DividendEntry(h.getInvestorId(), payout));
                    totalDistributed += payout;
                }
            }
        } catch (Exception e) {
            throw new ChaincodeException("failed to iterate holders: " + e.getMessage());
        }

        DividendRecord record = new DividendRecord(dividendId, perTokenAmount,
                totalDistributed, entries);
        stub.putState(DIVIDEND_PREFIX + dividendId, genson.serializeBytes(record));
        stub.setEvent("DividendDistributed", genson.serializeBytes(record));
        return genson.serialize(record);
    }

    @Transaction(intent = Transaction.TYPE.EVALUATE)
    public Holder getHolder(final Context ctx, final String investorId) {
        return loadHolder(ctx, investorId);
    }

    @Transaction(intent = Transaction.TYPE.EVALUATE)
    public String listHolders(final Context ctx) {
        ChaincodeStub stub = ctx.getStub();
        List<Holder> result = new ArrayList<>();
        try (QueryResultsIterator<KeyValue> it = stub.getStateByRange(
                HOLDER_PREFIX, HOLDER_PREFIX + "￿")) {
            for (KeyValue kv : it) {
                result.add(genson.deserialize(kv.getValue(), Holder.class));
            }
        } catch (Exception e) {
            throw new ChaincodeException("failed to list holders: " + e.getMessage());
        }
        return genson.serialize(result);
    }

    private SecurityToken loadToken(final Context ctx) {
        byte[] b = ctx.getStub().getState(TOKEN_KEY);
        if (b == null || b.length == 0) {
            throw new ChaincodeException("token not initialized",
                    Err.NOT_INITIALIZED.name());
        }
        return genson.deserialize(b, SecurityToken.class);
    }

    private Holder loadHolder(final Context ctx, final String investorId) {
        byte[] b = ctx.getStub().getState(HOLDER_PREFIX + investorId);
        if (b == null || b.length == 0) {
            throw new ChaincodeException("holder not found: " + investorId,
                    Err.HOLDER_NOT_FOUND.name());
        }
        return genson.deserialize(b, Holder.class);
    }

    private void requireIssuer(final Context ctx) {
        SecurityToken t = ctx.getStub().getState(TOKEN_KEY).length > 0
                ? loadToken(ctx) : null;
        String mspId = ctx.getClientIdentity().getMSPID();
        if (t != null && !t.getIssuer().equals(mspId)) {
            throw new ChaincodeException("only issuer MSP can perform this op",
                    Err.NOT_ISSUER.name());
        }
    }

    private void requirePositive(long amount) {
        if (amount <= 0) {
            throw new ChaincodeException("amount must be positive",
                    Err.INVALID_AMOUNT.name());
        }
    }

    private boolean isRestrictedCountry(String country) {
        if (country == null) return false;
        return "KP".equalsIgnoreCase(country) || "IR".equalsIgnoreCase(country);
    }
}
