package com.example.sto.rest;

import com.example.sto.rest.dto.Requests.*;
import com.example.sto.service.SecurityTokenService;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("/token")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class SecurityTokenResource {

    @Inject SecurityTokenService service;

    @POST @Path("/init")
    public Response init(InitTokenRequest req) throws Exception {
        return ok(service.initToken(req.symbol, req.name, req.decimals));
    }

    @GET
    public Response token() throws Exception {
        return ok(service.getToken());
    }

    @POST @Path("/holders")
    public Response registerHolder(RegisterHolderRequest req) throws Exception {
        return ok(service.registerHolder(req.investorId, req.kycVerified, req.country));
    }

    @PUT @Path("/holders/{id}/kyc")
    public Response kyc(@PathParam("id") String id, KycRequest req) throws Exception {
        return ok(service.updateKyc(id, req.kycVerified));
    }

    @GET @Path("/holders")
    public Response listHolders() throws Exception {
        return ok(service.listHolders());
    }

    @GET @Path("/holders/{id}")
    public Response holder(@PathParam("id") String id) throws Exception {
        return ok(service.getHolder(id));
    }

    @POST @Path("/issue")
    public Response issue(IssueRequest req) throws Exception {
        return ok(service.issue(req.investorId, req.amount));
    }

    @POST @Path("/transfer")
    public Response transfer(TransferRequest req) throws Exception {
        return ok(service.transfer(req.fromId, req.toId, req.amount));
    }

    @POST @Path("/burn")
    public Response burn(AmountRequest req) throws Exception {
        return ok(service.burn(req.investorId, req.amount));
    }

    @POST @Path("/lock")
    public Response lock(AmountRequest req) throws Exception {
        return ok(service.lock(req.investorId, req.amount));
    }

    @POST @Path("/unlock")
    public Response unlock(AmountRequest req) throws Exception {
        return ok(service.unlock(req.investorId, req.amount));
    }

    @POST @Path("/pause")
    public Response pause(PauseRequest req) throws Exception {
        return ok(service.pause(req.paused));
    }

    @POST @Path("/dividend")
    public Response dividend(DividendRequest req) throws Exception {
        return ok(service.distributeDividend(req.dividendId, req.perTokenAmount));
    }

    private Response ok(String body) {
        return Response.ok(body, MediaType.APPLICATION_JSON).build();
    }
}
