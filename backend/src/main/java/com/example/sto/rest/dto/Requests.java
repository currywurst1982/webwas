package com.example.sto.rest.dto;

public class Requests {

    public static class InitTokenRequest {
        public String symbol;
        public String name;
        public int decimals;
    }

    public static class RegisterHolderRequest {
        public String investorId;
        public boolean kycVerified;
        public String country;
    }

    public static class KycRequest {
        public boolean kycVerified;
    }

    public static class IssueRequest {
        public String investorId;
        public long amount;
    }

    public static class TransferRequest {
        public String fromId;
        public String toId;
        public long amount;
    }

    public static class AmountRequest {
        public String investorId;
        public long amount;
    }

    public static class PauseRequest {
        public boolean paused;
    }

    public static class DividendRequest {
        public String dividendId;
        public long perTokenAmount;
    }
}
