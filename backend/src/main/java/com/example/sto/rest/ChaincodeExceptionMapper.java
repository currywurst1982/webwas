package com.example.sto.rest;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import org.hyperledger.fabric.client.EndorseException;
import org.hyperledger.fabric.client.SubmitException;

@Provider
public class ChaincodeExceptionMapper implements ExceptionMapper<Exception> {
    @Override
    public Response toResponse(Exception ex) {
        int status = (ex instanceof EndorseException || ex instanceof SubmitException)
                ? 400 : 500;
        String msg = "{\"error\":\"" + escape(ex.getMessage()) + "\"}";
        return Response.status(status).type(MediaType.APPLICATION_JSON).entity(msg).build();
    }

    private String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
